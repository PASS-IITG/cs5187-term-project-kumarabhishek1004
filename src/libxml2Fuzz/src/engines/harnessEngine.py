"""Engine 3a: LLM harness generation with machine quality gates and a coverage-feedback improvement loop."""
import json
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from src.core.appConfig import AppConfig, templatesDir
from src.core.appLogger import getLogger, logEvent
from src.core.hypothesisStore import Hypothesis
from src.core.llmClient import AllProvidersExhaustedError, LlmError, LlmRouter
from src.core.shellRunner import runCommand
from src.core.textUtils import extractCodeBlock, makeSafeName, tailLines, truncateText
from src.infra.coverageAnalyzer import CoverageAnalyzer, FunctionCoverage
from src.infra.libxmlBuilder import LibxmlBuilder
from src.infra.sourceIndexer import SourceIndexer
from src.prompts import promptLibrary
from src.triage.crashTriage import CrashTriage, containsSanitizerFailure

logger = getLogger("harness")


@dataclass
class HarnessRecord:
    name: str
    directory: Path
    targetFunctions: List[str]
    sourcePath: Path = field(init=False)
    binaryPath: Path = field(init=False)
    coverageBinaryPath: Path = field(init=False)
    corpusDir: Path = field(init=False)
    seedsDir: Path = field(init=False)
    artifactsDir: Path = field(init=False)
    dictionaryPath: Path = field(init=False)
    coverageScore: float = 0.0

    def __post_init__(self):
        self.sourcePath = self.directory / "harness.cc"
        self.binaryPath = self.directory / "bin" / "harnessFuzzer"
        self.coverageBinaryPath = self.directory / "bin" / "harnessCoverage"
        self.corpusDir = self.directory / "corpus"
        self.seedsDir = self.directory / "seeds"
        self.artifactsDir = self.directory / "artifacts"
        self.dictionaryPath = self.directory / "dictionary.txt"
        for directory in (self.directory / "bin", self.corpusDir, self.seedsDir, self.artifactsDir):
            directory.mkdir(parents=True, exist_ok=True)


def parseExecutedUnits(libFuzzerOutput: str) -> int:
    match = re.search(r"stat::number_of_executed_units:\s+(\d+)", libFuzzerOutput)
    return int(match.group(1)) if match else 0


class HarnessEngine:
    def __init__(self, config: AppConfig, router: LlmRouter, indexer: SourceIndexer, builder: LibxmlBuilder,
                 coverageAnalyzer: CoverageAnalyzer, crashTriage: CrashTriage):
        self.config = config
        self.router = router
        self.indexer = indexer
        self.builder = builder
        self.coverageAnalyzer = coverageAnalyzer
        self.crashTriage = crashTriage
        self.harnessRoot = config.getPath("paths.workDir") / "harnesses"
        self.referenceHarness = (templatesDir / "referenceHarnessDomMutation.cc").read_text(encoding="utf-8")
        self.maxRepairAttempts = config.get("harness.maxCompileRepairAttempts", 3)

    # ------------------------------------------------------------------ public entry points
    def createHarnessForComponent(self, componentName: str, functionNames: List[str]) -> Optional[HarnessRecord]:
        goal = "Goal: exercise as many of these under-tested APIs as possible, including unusual option combinations and call orders."
        return self._createHarness(f"comp_{makeSafeName(componentName)}", componentName, functionNames, goal)

    def createHarnessForHypothesis(self, hypothesis: Hypothesis) -> Optional[HarnessRecord]:
        """Interconnection: an audit suspicion that no PoC could trigger becomes a targeted fuzz harness."""
        entryPoints = self.indexer.findPublicApiEntryPoints(hypothesis.functionName)
        targets = entryPoints or [hypothesis.functionName]
        goal = (f"Goal: reach the internal function '{hypothesis.functionName}' through these public APIs and stress its error paths. "
                f"Suspected issue: {hypothesis.description[:600]}")
        return self._createHarness(f"hyp{hypothesis.id}_{makeSafeName(hypothesis.functionName, 30)}",
                                   hypothesis.functionName, targets + [hypothesis.functionName], goal)

    def installReferenceHarness(self) -> Optional[HarnessRecord]:
        """Installs the hand-written DOM-mutation + allocation-failure harness (needs NO LLM tokens) as a ready-to-fuzz harness."""
        targetFunctions = ["xmlNewDoc", "xmlNewDocNode", "xmlDocSetRootElement", "xmlAddChild", "xmlUnlinkNode", "xmlReplaceNode",
                           "xmlNodeSetContent", "xmlSetProp", "xmlNewNs", "xmlSetNs", "xmlCopyNode", "xmlNodeSetName",
                           "xmlAddNextSibling", "xmlAddPrevSibling", "xmlSaveToBuffer", "xmlSaveDoc", "xmlFreeNode", "xmlFreeDoc"]
        directory = self.harnessRoot / "reference_domMutation"
        if directory.exists():
            shutil.rmtree(directory)
        record = HarnessRecord("reference_domMutation", directory, targetFunctions)
        shutil.copy(templatesDir / "referenceHarnessDomMutation.cc", record.sourcePath)
        problemKind, problemOutput = self._runAllGatesOnce(record, record.sourcePath.read_text(encoding="utf-8"))
        if problemKind is not None:
            logger.error("Reference harness failed gate '%s': %s", problemKind, truncateText(problemOutput, 1500))
            return None
        (record.directory / "targets.json").write_text(json.dumps({"targetFunctions": targetFunctions, "coverageScore": record.coverageScore}))
        logger.info("Reference harness installed at %s (target coverage %.0f%%). Start it with: python main.py fuzz --hours N",
                    directory, record.coverageScore * 100)
        return record

    def loadExistingHarnesses(self) -> List[HarnessRecord]:
        """Re-discovers harnesses generated in earlier runs (so the fuzzing phase can run on its own)."""
        records: List[HarnessRecord] = []
        for targetsFile in sorted(self.harnessRoot.glob("*/targets.json")):
            targetInfo = json.loads(targetsFile.read_text())
            record = HarnessRecord(targetsFile.parent.name, targetsFile.parent, targetInfo["targetFunctions"])
            record.coverageScore = targetInfo.get("coverageScore", 0.0)
            if not record.binaryPath.exists():
                self.builder.compileFuzzHarness("asanUbsan", record.sourcePath, record.binaryPath)
            if record.binaryPath.exists():
                records.append(record)
        logger.info("Loaded %d existing harnesses from disk", len(records))
        return records

    # ------------------------------------------------------------------ pipeline
    def _createHarness(self, harnessName: str, componentName: str, functionNames: List[str], goal: str) -> Optional[HarnessRecord]:
        logger.info("==== Generating harness '%s' for %d target functions", harnessName, len(functionNames))
        directory = self.harnessRoot / harnessName
        if directory.exists():
            shutil.rmtree(directory)
        record = HarnessRecord(harnessName, directory, functionNames)
        declarations = [self.indexer.getHeaderDeclaration(name) for name in functionNames if self.indexer.getHeaderDeclaration(name)]
        if not declarations:
            logger.warning("No public declarations found for %s; harness skipped", harnessName)
            return None
        try:
            sourceCode = self._generateInitialSource(componentName, declarations, goal)
            if sourceCode is None:
                return None
            record.sourcePath.write_text(sourceCode, encoding="utf-8")
            if not self.passQualityGates(record):
                logger.warning("Harness '%s' DROPPED: it did not pass the quality gates", harnessName)
                logEvent("harnessDropped", harness=harnessName)
                return None
            self.improveWithCoverage(record)
            self.generateSeedsAndDictionary(record, componentName, declarations)
        except AllProvidersExhaustedError:
            raise
        except LlmError as llmError:
            logger.error("Harness '%s' aborted because of LLM failure: %s", harnessName, llmError)
            return None
        (record.directory / "targets.json").write_text(json.dumps({"targetFunctions": functionNames, "coverageScore": record.coverageScore}))
        logger.info("Harness '%s' READY (target coverage %.0f%%)", harnessName, record.coverageScore * 100)
        logEvent("harnessReady", harness=harnessName, coverageScore=round(record.coverageScore, 3))
        return record

    def _generateInitialSource(self, componentName: str, declarations: List[str], goal: str) -> Optional[str]:
        reply = self.router.askText("generator", promptLibrary.systemCodeWriter,
                                    promptLibrary.buildHarnessPrompt(componentName, declarations, self.referenceHarness, goal),
                                    temperature=0.4, maxTokens=8000)
        sourceCode = extractCodeBlock(reply, ["cpp", "c++", "cc", "c"])
        if sourceCode is None:
            logger.error("Generator returned no code block for %s", componentName)
            return None
        if self.config.get("harness.useExtender", True):
            missingApis = [decl for decl in declarations if not self._declarationIsUsed(decl, sourceCode)]
            if missingApis:
                logger.info("Extender LLM will add %d APIs the generator missed", len(missingApis))
                extended = self.router.askText("extender", promptLibrary.systemCodeWriter,
                                               promptLibrary.buildHarnessExtensionPrompt(sourceCode, missingApis[:15]),
                                               temperature=0.3, maxTokens=8000)
                extendedCode = extractCodeBlock(extended, ["cpp", "c++", "cc", "c"])
                sourceCode = extendedCode or sourceCode
        return sourceCode

    @staticmethod
    def _declarationIsUsed(declaration: str, sourceCode: str) -> bool:
        match = re.search(r"\b(\w+)\s*\(", declaration.split(":", 1)[-1])
        return bool(match) and re.search(r"\b" + re.escape(match.group(1)) + r"\b", sourceCode) is not None

    # ------------------------------------------------------------------ gates
    def staticSanityCheck(self, sourceCode: str) -> Optional[str]:
        if "LLVMFuzzerTestOneInput" not in sourceCode:
            return "missing LLVMFuzzerTestOneInput"
        if re.search(r"\bint\s+main\s*\(", sourceCode):
            return "must not define main()"
        if "fuzzAllocator.h" not in sourceCode:
            return 'must include "fuzzAllocator.h" and use allocation-failure injection'
        if "FuzzedDataProvider" not in sourceCode:
            return "must use FuzzedDataProvider"
        return None

    def passQualityGates(self, record: HarnessRecord) -> bool:
        """Gate order: static sanity -> compile -> smoke run (no crash, fast enough) -> reaches target functions."""
        for attemptNumber in range(1, self.maxRepairAttempts + 2):
            sourceCode = record.sourcePath.read_text(encoding="utf-8")
            problemKind, problemOutput = self._runAllGatesOnce(record, sourceCode)
            if problemKind is None:
                logger.info("Harness '%s' passed all gates (attempt %d)", record.name, attemptNumber)
                logEvent("harnessGatesPassed", harness=record.name, attempts=attemptNumber)
                return True
            logger.warning("Harness '%s' failed gate '%s' (attempt %d/%d)", record.name, problemKind, attemptNumber, self.maxRepairAttempts + 1)
            logEvent("harnessGateFailed", harness=record.name, gate=problemKind.split(":")[0], attempt=attemptNumber)
            (record.directory / "lastGateFailure.txt").write_text(f"{problemKind}\n\n{problemOutput}", encoding="utf-8")
            logger.warning("Gate '%s' details for '%s' (full text in %s):\n%s", problemKind.split(":")[0], record.name,
                           record.directory / "lastGateFailure.txt", "\n".join(problemOutput.splitlines()[:8]))
            if attemptNumber > self.maxRepairAttempts:
                break
            repaired = self.router.askText("generator", promptLibrary.systemCodeWriter,
                                           promptLibrary.buildHarnessRepairPrompt(sourceCode, problemKind, problemOutput),
                                           temperature=0.3, maxTokens=8000)
            repairedCode = extractCodeBlock(repaired, ["cpp", "c++", "cc", "c"])
            if repairedCode is None:
                logger.error("Repair attempt returned no code block")
                break
            record.sourcePath.write_text(repairedCode, encoding="utf-8")
        return False

    def _runAllGatesOnce(self, record: HarnessRecord, sourceCode: str) -> Tuple[Optional[str], str]:
        sanityProblem = self.staticSanityCheck(sourceCode)
        if sanityProblem:
            return f"static check: {sanityProblem}", sanityProblem
        compileResult = self.builder.compileFuzzHarness("asanUbsan", record.sourcePath, record.binaryPath)
        if not compileResult.succeeded:
            return "compile error", tailLines(compileResult.stderr, 30)
        smokeSeconds = self.config.get("harness.smokeRunSeconds", 30)
        smokeResult = self.runShortFuzz(record, smokeSeconds)
        if containsSanitizerFailure(smokeResult.combinedOutput):
            return self._handleSmokeCrash(record, smokeResult.combinedOutput)
        executedUnits = parseExecutedUnits(smokeResult.combinedOutput)
        execsPerSecond = executedUnits / max(smokeSeconds, 1)
        minimumSpeed = self.config.get("harness.minExecsPerSecond", 50)
        logger.info("Smoke run of '%s': %d execs (%.0f/s)", record.name, executedUnits, execsPerSecond)
        if execsPerSecond < minimumSpeed:
            return "too slow", f"only {execsPerSecond:.0f} execs/s (minimum {minimumSpeed}); remove expensive work per input"
        coverageByName = self.measureCoverage(record)[0]
        record.coverageScore = CoverageAnalyzer.computeAverageRatio(coverageByName, record.targetFunctions)
        if record.coverageScore == 0.0:
            return "targets never reached", "none of the target functions executed during the smoke run; call them with valid arguments"
        return None, ""

    def _handleSmokeCrash(self, record: HarnessRecord, crashOutput: str) -> Tuple[str, str]:
        """A crash in the first seconds is usually a harness mistake, but it might be a real library bug: vote first."""
        crashFiles = sorted(record.artifactsDir.glob("crash-*")) + sorted(record.artifactsDir.glob("leak-*")) + sorted(record.artifactsDir.glob("oom-*"))
        if crashFiles:
            self.crashTriage.processFuzzCrashes(record.name, record.binaryPath, record.sourcePath, crashFiles[:3])
            for crashFile in crashFiles:
                shutil.move(str(crashFile), str(record.directory / ("handled_" + crashFile.name)))
        return "crash during smoke run (likely harness ownership bug)", truncateText(crashOutput, 3500)

    def runShortFuzz(self, record: HarnessRecord, seconds: int):
        arguments = [str(record.binaryPath), str(record.corpusDir)]
        if any(record.seedsDir.iterdir()):
            arguments.append(str(record.seedsDir))
        arguments += [f"-max_total_time={seconds}", f"-timeout={self.config.get('fuzzing.timeoutPerInputSeconds', 10)}",
                      f"-rss_limit_mb={self.config.get('fuzzing.rssLimitMb', 2048)}",
                      f"-max_len={self.config.get('fuzzing.maxInputLength', 4096)}",
                      f"-artifact_prefix={record.artifactsDir}/", "-print_final_stats=1"]
        if record.dictionaryPath.exists():
            arguments.append(f"-dict={record.dictionaryPath}")
        return runCommand(arguments, timeoutSeconds=seconds + 120, logFailures=False)

    # ------------------------------------------------------------------ coverage feedback loop
    def measureCoverage(self, record: HarnessRecord) -> Tuple[Dict[str, FunctionCoverage], Optional[Path]]:
        compileResult = self.builder.compileFuzzHarness("coverage", record.sourcePath, record.coverageBinaryPath)
        if not compileResult.succeeded:
            logger.error("Coverage build of '%s' failed: %s", record.name, tailLines(compileResult.stderr, 10))
            return {}, None
        profileDir = record.directory / "coverageData"
        profdataPath = self.coverageAnalyzer.generateProfile(record.coverageBinaryPath, [record.corpusDir, record.seedsDir], profileDir)
        if profdataPath is None:
            return {}, None
        return self.coverageAnalyzer.exportFunctionCoverage(record.coverageBinaryPath, profdataPath), profdataPath

    def improveWithCoverage(self, record: HarnessRecord) -> None:
        """Your original idea: tell the LLM which APIs/lines are poorly covered and let it extend the driver."""
        goal = self.config.get("harness.targetFunctionCoverageGoal", 0.6)
        for roundNumber in range(1, self.config.get("harness.improvementRounds", 2) + 1):
            self.runShortFuzz(record, self.config.get("harness.improvementRoundSeconds", 300))
            coverageByName, profdataPath = self.measureCoverage(record)
            if profdataPath is None:
                return
            record.coverageScore = CoverageAnalyzer.computeAverageRatio(coverageByName, record.targetFunctions)
            logger.info("Improvement round %d for '%s': target coverage %.0f%% (goal %.0f%%)", roundNumber, record.name,
                        record.coverageScore * 100, goal * 100)
            logEvent("coverageRound", harness=record.name, round=roundNumber, score=round(record.coverageScore, 3))
            if record.coverageScore >= goal:
                return
            uncoveredReport = self._buildUncoveredReport(record, coverageByName, profdataPath)
            if not uncoveredReport:
                return
            previousSource = record.sourcePath.read_text(encoding="utf-8")
            previousScore = record.coverageScore
            reply = self.router.askText("generator", promptLibrary.systemCodeWriter,
                                        promptLibrary.buildCoverageImprovementPrompt(previousSource, uncoveredReport),
                                        temperature=0.4, maxTokens=8000)
            improvedCode = extractCodeBlock(reply, ["cpp", "c++", "cc", "c"])
            if improvedCode is None:
                return
            record.sourcePath.write_text(improvedCode, encoding="utf-8")
            if not self.passQualityGates(record) or record.coverageScore < previousScore:
                logger.info("Improved version of '%s' was not better (%.0f%% -> %.0f%%); reverting", record.name,
                            previousScore * 100, record.coverageScore * 100)
                record.sourcePath.write_text(previousSource, encoding="utf-8")
                self.builder.compileFuzzHarness("asanUbsan", record.sourcePath, record.binaryPath)
                record.coverageScore = previousScore
                return

    def _buildUncoveredReport(self, record: HarnessRecord, coverageByName: Dict[str, FunctionCoverage], profdataPath: Path) -> str:
        weakFunctions = sorted(record.targetFunctions, key=lambda name: coverageByName[name].ratio if name in coverageByName else 0.0)[:5]
        sections = []
        budget = self.config.get("harness.maxUncoveredSnippetChars", 6000)
        for functionName in weakFunctions:
            ratio = coverageByName[functionName].ratio if functionName in coverageByName else 0.0
            if ratio >= 0.95:
                continue
            snippet = self.coverageAnalyzer.showUncoveredSource(record.coverageBinaryPath, profdataPath, functionName, budget // 5)
            sections.append(f"### {functionName} ({ratio:.0%} covered)\nDeclaration: {self.indexer.getHeaderDeclaration(functionName)}\n"
                            f"Never-executed lines:\n{snippet or '(function never called by the harness)'}")
        return "\n\n".join(sections)

    # ------------------------------------------------------------------ seeds
    def generateSeedsAndDictionary(self, record: HarnessRecord, componentName: str, declarations: List[str]) -> None:
        try:
            reply = self.router.askJson("generator", promptLibrary.systemCodeWriter,
                                        promptLibrary.buildSeedPrompt(componentName, declarations), temperature=0.7, maxTokens=6000)
        except AllProvidersExhaustedError:
            raise
        except LlmError as llmError:
            logger.warning("Seed generation skipped for '%s': %s", record.name, llmError)
            return
        for index, seed in enumerate((reply.get("seeds") or [])[:12]):
            (record.seedsDir / f"seed{index}_{makeSafeName(str(seed.get('name', 'seed')), 20)}").write_text(str(seed.get("content", "")), encoding="utf-8")
        tokens = [str(token) for token in (reply.get("dictionaryTokens") or [])[:60] if str(token)]
        record.dictionaryPath.write_text("\n".join(self._formatDictionaryEntry(token) for token in tokens) + "\n", encoding="utf-8")
        logger.info("Wrote %d seeds and %d dictionary tokens for '%s'", len(list(record.seedsDir.iterdir())), len(tokens), record.name)

    @staticmethod
    def _formatDictionaryEntry(token: str) -> str:
        escaped = "".join(ch if 32 <= ord(ch) < 127 and ch not in '"\\' else "\\x%02x" % (ord(ch) & 0xFF) for ch in token)
        return f'"{escaped}"'
