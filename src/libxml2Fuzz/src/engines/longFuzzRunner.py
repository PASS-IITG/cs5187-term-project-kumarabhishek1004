"""Engine 3b: long fuzzing in chunks with libFuzzer fork mode, plateau detection and crash collection."""
import random
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from src.core.appConfig import AppConfig
from src.core.appLogger import getLogger, logEvent
from src.core.shellRunner import runCommand
from src.engines.harnessEngine import HarnessRecord, parseExecutedUnits

logger = getLogger("fuzzRun")
counterPattern = re.compile(r"#\d+:?\s+(?:[A-Z_]+\s+)?cov:\s+(\d+)\s+ft:\s+(\d+)")
crashPrefixes = ("crash-", "leak-", "oom-", "timeout-", "slow-unit-")


@dataclass
class FuzzChunkResult:
    coverage: int
    features: int
    executedUnits: int
    newCrashFiles: List[Path] = field(default_factory=list)
    returnCode: int = 0


def parseLibFuzzerCounters(outputText: str) -> Tuple[int, int]:
    """Returns the last (cov, ft) pair printed by libFuzzer, or (0, 0)."""
    matches = counterPattern.findall(outputText)
    return (int(matches[-1][0]), int(matches[-1][1])) if matches else (0, 0)


class LongFuzzRunner:
    def __init__(self, config: AppConfig):
        self.config = config

    def runChunk(self, record: HarnessRecord, chunkSeconds: int) -> FuzzChunkResult:
        workers = self.config.get("fuzzing.workersPerHarness", 4)
        arguments = [str(record.binaryPath), str(record.corpusDir)]
        if any(record.seedsDir.iterdir()):
            arguments.append(str(record.seedsDir))
        if workers > 1:
            arguments += [f"-fork={workers}", "-ignore_crashes=1"]
        arguments += [f"-max_total_time={chunkSeconds}", f"-timeout={self.config.get('fuzzing.timeoutPerInputSeconds', 10)}",
                      f"-rss_limit_mb={self.config.get('fuzzing.rssLimitMb', 2048)}",
                      f"-max_len={self.config.get('fuzzing.maxInputLength', 4096)}",
                      f"-artifact_prefix={record.artifactsDir}/", "-print_final_stats=1"]
        if record.dictionaryPath.exists():
            arguments.append(f"-dict={record.dictionaryPath}")
        logger.info("Fuzzing '%s' for %ds with %d worker(s) ...", record.name, chunkSeconds, workers)
        result = runCommand(arguments, workingDir=record.directory, timeoutSeconds=chunkSeconds + 600, logFailures=False)
        (record.directory / "lastChunk.log").write_text(result.combinedOutput[-20000:], encoding="utf-8")
        coverage, features = parseLibFuzzerCounters(result.combinedOutput)
        newCrashFiles = self.collectUnprocessedCrashes(record)
        logger.info("Chunk done for '%s': cov=%d ft=%d crashes=%d exit=%d", record.name, coverage, features,
                    len(newCrashFiles), result.returnCode)
        if result.timedOut:
            logger.warning("Chunk for '%s' overran its time limit and was killed", record.name)
        logEvent("fuzzChunk", harness=record.name, coverage=coverage, features=features, crashes=len(newCrashFiles))
        return FuzzChunkResult(coverage, features, parseExecutedUnits(result.combinedOutput), newCrashFiles, result.returnCode)

    def collectUnprocessedCrashes(self, record: HarnessRecord) -> List[Path]:
        return sorted(path for path in record.artifactsDir.iterdir() if path.is_file() and path.name.startswith(crashPrefixes))

    def markCrashesProcessed(self, record: HarnessRecord, crashFiles: List[Path]) -> None:
        processedDir = record.artifactsDir / "processed"
        processedDir.mkdir(exist_ok=True)
        for crashFile in crashFiles:
            if crashFile.exists():
                shutil.move(str(crashFile), str(processedDir / crashFile.name))
            minimizedFile = crashFile.with_name(crashFile.name + ".min")
            if minimizedFile.exists():
                shutil.move(str(minimizedFile), str(processedDir / minimizedFile.name))

    def mergeCorpusDirectories(self, record: HarnessRecord, otherCorpusDirs: List[Path]) -> None:
        """Merges corpora from other machines into this harness's corpus (keeps only coverage-increasing inputs)."""
        sources = [str(path) for path in otherCorpusDirs if path.exists()]
        if not sources:
            return
        mergedDir = record.directory / "corpusMerged"
        mergedDir.mkdir(exist_ok=True)
        result = runCommand([str(record.binaryPath), "-merge=1", str(mergedDir), str(record.corpusDir)] + sources, timeoutSeconds=3600)
        if result.succeeded:
            shutil.rmtree(record.corpusDir)
            mergedDir.rename(record.corpusDir)
            logger.info("Merged %d external corpora into '%s'", len(sources), record.name)


class FuzzScheduler:
    """Epsilon-greedy bandit: spend the next chunk on the harness whose coverage grew most recently.

    A harness is retired only when (a) it has gone `plateauSeconds` of ITS OWN fuzzing time without any new coverage, or
    (b) an optional per-harness time cap (budgetSecondsPerHarness > 0) is used up. As long as coverage keeps growing it keeps
    getting CPU time until the campaign deadline.
    """

    def __init__(self, harnessNames: List[str], explorationRate: float, plateauSeconds: int, budgetSecondsPerHarness: int):
        self.explorationRate = explorationRate
        self.plateauSeconds = plateauSeconds
        self.budgetSeconds = budgetSecondsPerHarness
        self.lastCoverage: Dict[str, int] = {name: 0 for name in harnessNames}
        self.growthScore: Dict[str, float] = {}
        self.secondsSpent: Dict[str, int] = {name: 0 for name in harnessNames}
        self.secondsSinceGrowth: Dict[str, int] = {name: 0 for name in harnessNames}
        self.retired: Dict[str, str] = {}

    def chooseNext(self) -> Optional[str]:
        activeNames = [name for name in self.lastCoverage if name not in self.retired]
        if not activeNames:
            return None
        unseenNames = [name for name in activeNames if name not in self.growthScore]
        if unseenNames:
            return unseenNames[0]
        if random.random() < self.explorationRate:
            return random.choice(activeNames)
        return max(activeNames, key=lambda name: self.growthScore[name])

    def reportChunk(self, harnessName: str, chunkSeconds: int, coverage: int) -> None:
        gain = coverage - self.lastCoverage[harnessName]
        self.lastCoverage[harnessName] = max(coverage, self.lastCoverage[harnessName])
        previousScore = self.growthScore.get(harnessName, float(gain))
        self.growthScore[harnessName] = 0.5 * previousScore + 0.5 * gain
        self.secondsSpent[harnessName] += chunkSeconds
        self.secondsSinceGrowth[harnessName] = 0 if gain > 0 else self.secondsSinceGrowth[harnessName] + chunkSeconds
        logger.info("Scheduler: '%s' gain=%+d cov=%d, %ds fuzzed in total, %ds since last growth", harnessName, gain,
                    coverage, self.secondsSpent[harnessName], self.secondsSinceGrowth[harnessName])
        if self.budgetSeconds > 0 and self.secondsSpent[harnessName] >= self.budgetSeconds:
            self._retire(harnessName, "time budget used")
        elif self.secondsSinceGrowth[harnessName] >= self.plateauSeconds:
            self._retire(harnessName, f"coverage plateau (no new coverage during {self.plateauSeconds}s of its own fuzzing)")

    def _retire(self, harnessName: str, reason: str) -> None:
        self.retired[harnessName] = reason
        logger.info("Harness '%s' RETIRED: %s", harnessName, reason)
        logEvent("harnessRetired", harness=harnessName, reason=reason)
