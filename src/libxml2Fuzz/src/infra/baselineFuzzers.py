"""Builds and runs libxml2's own upstream fuzz harnesses (free background baseline) and measures their coverage."""
import re
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Tuple

from src.core.appConfig import AppConfig
from src.core.appLogger import getLogger, logEvent
from src.infra.coverageAnalyzer import CoverageAnalyzer, FunctionCoverage
from src.infra.libxmlBuilder import LibxmlBuilder
from src.core.textUtils import tailLines

logger = getLogger("baseline")


class BaselineFuzzers:
    def __init__(self, config: AppConfig, builder: LibxmlBuilder, coverageAnalyzer: CoverageAnalyzer):
        self.config = config
        self.builder = builder
        self.coverageAnalyzer = coverageAnalyzer
        self.fuzzSourceDir = config.getPath("paths.libxml2Dir") / "fuzz"
        self.baselineDir = config.getPath("paths.workDir") / "baseline"
        self.runningProcesses: Dict[str, subprocess.Popen] = {}

    def discoverUpstreamHarnesses(self) -> List[Path]:
        if not self.fuzzSourceDir.exists():
            logger.error("Upstream fuzz directory not found: %s", self.fuzzSourceDir)
            return []
        harnesses = [path for path in sorted(self.fuzzSourceDir.glob("*.c")) if "LLVMFuzzerTestOneInput" in path.read_text(errors="replace")]
        logger.info("Found %d upstream harnesses: %s", len(harnesses), ", ".join(path.stem for path in harnesses))
        return harnesses

    def buildAll(self, variantName: str = "asanUbsan") -> Dict[str, Path]:
        helperSource = self.fuzzSourceDir / "fuzz.c"
        builtBinaries: Dict[str, Path] = {}
        for harnessPath in self.discoverUpstreamHarnesses():
            outputPath = self.baselineDir / variantName / harnessPath.stem
            result = self.builder.compileFuzzHarness(variantName, harnessPath, outputPath,
                                                     extraSources=[helperSource] if helperSource.exists() else None)
            if result.succeeded:
                builtBinaries[harnessPath.stem] = outputPath
            else:
                logger.warning("Upstream harness %s failed to build: %s", harnessPath.name, tailLines(result.stderr, 6))
        logger.info("Built %d/%d upstream harnesses (%s)", len(builtBinaries), len(self.discoverUpstreamHarnesses()), variantName)
        return builtBinaries

    def startBackgroundFuzzing(self, durationHours: float) -> int:
        """Starts one fork-mode libFuzzer process per harness; cores are split evenly. Returns processes started."""
        binaries = self.buildAll("asanUbsan")
        if not binaries:
            return 0
        coresPerHarness = max(1, self.config.get("fuzzing.baselineCoresTotal", 8) // len(binaries))
        for harnessName, binaryPath in binaries.items():
            corpusDir = self.baselineDir / "corpus" / harnessName
            artifactsDir = self.baselineDir / "artifacts" / harnessName
            for directory in (corpusDir, artifactsDir):
                directory.mkdir(parents=True, exist_ok=True)
            seedDir = self.fuzzSourceDir / "seed" / harnessName
            arguments = [str(binaryPath), str(corpusDir)] + ([str(seedDir)] if seedDir.exists() else [])
            arguments += [f"-fork={coresPerHarness}", "-ignore_crashes=1", f"-max_total_time={int(durationHours * 3600)}",
                          f"-timeout={self.config.get('fuzzing.timeoutPerInputSeconds', 10)}",
                          f"-rss_limit_mb={self.config.get('fuzzing.rssLimitMb', 2048)}", f"-artifact_prefix={artifactsDir}/"]
            logFile = open(self.baselineDir / f"{harnessName}.log", "w")
            self.runningProcesses[harnessName] = subprocess.Popen(arguments, stdout=logFile, stderr=subprocess.STDOUT, cwd=str(self.baselineDir))
            logger.info("Baseline fuzzer started: %s with %d cores for %.1fh", harnessName, coresPerHarness, durationHours)
        logEvent("baselineStarted", harnessCount=len(binaries), hours=durationHours)
        return len(binaries)

    def stopBackgroundFuzzing(self) -> None:
        for process in self.runningProcesses.values():
            if process.poll() is None:
                process.terminate()
        self.runningProcesses.clear()
        logger.info("Baseline fuzzers stopped")

    def readLatestCounters(self, harnessName: str) -> Tuple[int, int]:
        """Latest 'cov' and 'ft' printed by a running baseline fuzzer (read from the tail of its log)."""
        logPath = self.baselineDir / f"{harnessName}.log"
        if not logPath.exists():
            return 0, 0
        with open(logPath, "rb") as logFile:
            logFile.seek(0, 2)
            logFile.seek(max(0, logFile.tell() - 60000))
            tailText = logFile.read().decode("utf-8", errors="replace")
        matches = re.findall(r"cov:\s+(\d+)\s+ft:\s+(\d+)", tailText)
        return (int(matches[-1][0]), int(matches[-1][1])) if matches else (0, 0)

    def waitForCompletion(self, reportEverySeconds: int = 600) -> None:
        """Blocks until all baseline fuzzers exit (or Ctrl+C). Logs coverage per harness so you can see when growth flattens."""
        lastReportTime = 0.0
        zeroCoverageReports: Dict[str, int] = {}
        while any(process.poll() is None for process in self.runningProcesses.values()):
            if time.time() - lastReportTime >= reportEverySeconds:
                lastReportTime = time.time()
                for harnessName, process in self.runningProcesses.items():
                    coverage, features = self.readLatestCounters(harnessName)
                    state = "running" if process.poll() is None else f"exited({process.returncode})"
                    logger.info("Baseline %-10s %-12s cov=%d ft=%d", harnessName, state, coverage, features)
                    zeroCoverageReports[harnessName] = zeroCoverageReports.get(harnessName, 0) + 1 if coverage == 0 and process.poll() is None else 0
                    if zeroCoverageReports[harnessName] >= 3:
                        logger.error("Baseline %s has shown NO coverage for ~%d minutes: it is probably failing at startup. "
                                     "Run: tail -n 20 %s   (typical cause: unsafe characters such as ( ) or spaces in the project path)",
                                     harnessName, 10 * (zeroCoverageReports[harnessName] - 1), self.baselineDir / f"{harnessName}.log")
            time.sleep(5)
        logger.info("All baseline fuzzers have finished")

    def collectBaselineCrashes(self) -> List[Path]:
        return sorted(path for path in (self.baselineDir / "artifacts").glob("*/*") if path.name.startswith(("crash-", "leak-", "oom-", "timeout-")))

    def measureBaselineCoverage(self) -> Dict[str, FunctionCoverage]:
        """Union (max per function) of the coverage reached by all upstream harnesses on their corpora."""
        mergedCoverage: Dict[str, FunctionCoverage] = {}
        helperSource = self.fuzzSourceDir / "fuzz.c"
        for harnessPath in self.discoverUpstreamHarnesses():
            coverageBinary = self.baselineDir / "coverage" / harnessPath.stem
            compileResult = self.builder.compileFuzzHarness("coverage", harnessPath, coverageBinary,
                                                            extraSources=[helperSource] if helperSource.exists() else None)
            if not compileResult.succeeded:
                continue
            corpusDirs = [self.baselineDir / "corpus" / harnessPath.stem, self.fuzzSourceDir / "seed" / harnessPath.stem]
            perHarness = self.coverageAnalyzer.measureFunctions(coverageBinary, corpusDirs, self.baselineDir / "coverageData" / harnessPath.stem)
            for name, functionCoverage in perHarness.items():
                existing = mergedCoverage.get(name)
                if existing is None or functionCoverage.coveredRegions > existing.coveredRegions:
                    mergedCoverage[name] = functionCoverage
        logger.info("Baseline coverage covers %d functions in total", len(mergedCoverage))
        return mergedCoverage
