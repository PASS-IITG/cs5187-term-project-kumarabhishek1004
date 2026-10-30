"""Crash handling: reproduce, deduplicate, minimize, adjudicate (harness bug vs library bug), write report."""
import re
import shutil
from pathlib import Path
from typing import List, Optional

from src.core.appConfig import AppConfig
from src.core.appLogger import getLogger, logEvent
from src.core.hypothesisStore import HypothesisStore
from src.core.shellRunner import CommandResult, runCommand
from src.core.textUtils import computeShortHash, makeSafeName, tailLines, truncateText
from src.prompts import promptLibrary
from src.triage.llmVoting import VotingPanel

logger = getLogger("triage")
sanitizerMarkers = ("ERROR: AddressSanitizer", "ERROR: LeakSanitizer", "ERROR: MemorySanitizer", "runtime error:",
                    "SUMMARY: UndefinedBehaviorSanitizer", "ERROR: libFuzzer: out-of-memory", "ERROR: libFuzzer: timeout",
                    "ERROR: libFuzzer: deadly signal")
frameLinePattern = re.compile(r"#\d+ 0x[0-9a-f]+ in (\w+)")
errorKindPattern = re.compile(r"(?:ERROR: \w+Sanitizer: |runtime error: |ERROR: libFuzzer: )([\w\- ]+)")


def containsSanitizerFailure(outputText: str) -> bool:
    return any(marker in outputText for marker in sanitizerMarkers)


class CrashTriage:
    def __init__(self, config: AppConfig, store: HypothesisStore, votingPanel: VotingPanel):
        self.config = config
        self.store = store
        self.votingPanel = votingPanel
        self.findingsDir = config.getPath("paths.workDir") / "findings"
        self.findingsDir.mkdir(parents=True, exist_ok=True)

    def computeSignature(self, sanitizerOutput: str) -> str:
        """Error kind + top library frames; two crashes with the same signature are treated as duplicates."""
        kindMatch = errorKindPattern.search(sanitizerOutput)
        errorKind = self._normalizeErrorKind(kindMatch.group(1)) if kindMatch else "unknownError"
        ignoredFrames = ("LLVMFuzzer", "fuzzer", "main", "__libc", "_start", "malloc", "free", "calloc", "realloc", "operator")
        libraryFrames = [name for name in frameLinePattern.findall(sanitizerOutput) if not name.startswith(ignoredFrames)]
        if libraryFrames:
            return errorKind + "__" + "_".join(libraryFrames[:3])
        return errorKind + "__" + computeShortHash(self._stripVolatileNumbers(sanitizerOutput[:600]))

    @staticmethod
    def _stripVolatileNumbers(text: str) -> str:
        """Removes addresses, pids and other run-specific numbers so equal bugs get equal signatures."""
        return re.sub(r"0x[0-9a-fA-F]+|\d+", "", text)

    def _normalizeErrorKind(self, rawKind: str) -> str:
        words = self._stripVolatileNumbers(rawKind).split()[:4]
        return makeSafeName("_".join(words), 40)

    def reproduceWithHarness(self, harnessBinary: Path, inputPath: Path) -> CommandResult:
        return runCommand([str(harnessBinary), str(inputPath)], timeoutSeconds=60, logFailures=False,
                          envOverrides={"ASAN_OPTIONS": "detect_leaks=1:symbolize=1", "UBSAN_OPTIONS": "print_stacktrace=1"})

    def minimizeInput(self, harnessBinary: Path, inputPath: Path, outputPath: Path) -> Path:
        result = runCommand([str(harnessBinary), "-minimize_crash=1", "-runs=3000", f"-exact_artifact_path={outputPath}",
                             str(inputPath)], timeoutSeconds=300, logFailures=False)
        if outputPath.exists():
            logger.info("Minimized crash input %s: %d -> %d bytes", inputPath.name, inputPath.stat().st_size, outputPath.stat().st_size)
            return outputPath
        logger.warning("Crash minimization produced no output; keeping original input (%s)", tailLines(result.stderr, 2))
        return inputPath

    def processFuzzCrashes(self, harnessName: str, harnessBinary: Path, harnessSourcePath: Path, crashFiles: List[Path]) -> int:
        confirmedCount = 0
        for crashFile in crashFiles:
            reproduction = self.reproduceWithHarness(harnessBinary, crashFile)
            if not containsSanitizerFailure(reproduction.combinedOutput) and not reproduction.timedOut:
                logger.warning("Crash %s does NOT reproduce standalone (flaky or environment-dependent); skipped", crashFile.name)
                continue
            signature = self.computeSignature(reproduction.combinedOutput)
            logEvent("crashReproduced", harness=harnessName, input=crashFile.name, signature=signature)
            minimizedPath = self.minimizeInput(harnessBinary, crashFile, crashFile.with_name(crashFile.name + ".min"))
            evidence = ("HARNESS SOURCE:\n" + truncateText(harnessSourcePath.read_text(errors="replace"), 7000)
                        + "\n\nSANITIZER OUTPUT:\n" + truncateText(reproduction.combinedOutput, 5000))
            if self._adjudicateAndRecord("fuzzCrash", f"{harnessName}__{signature}", harnessName, evidence,
                                         [minimizedPath, harnessSourcePath], reproduction.combinedOutput):
                confirmedCount += 1
        return confirmedCount

    def processPocFinding(self, hypothesisId: int, hypothesisTitle: str, pocSourcePath: Path, sanitizerOutput: str,
                          suspicionSummary: str) -> bool:
        signature = self.computeSignature(sanitizerOutput)
        evidence = (f"SUSPICION: {suspicionSummary}\n\nPOC SOURCE:\n" + truncateText(pocSourcePath.read_text(errors="replace"), 7000)
                    + "\n\nSANITIZER OUTPUT:\n" + truncateText(sanitizerOutput, 5000))
        return self._adjudicateAndRecord("pocFinding", f"poc{hypothesisId}__{signature}", f"hypothesis#{hypothesisId} {hypothesisTitle}",
                                         evidence, [pocSourcePath], sanitizerOutput)

    def recordLogicCandidate(self, signature: str, title: str, evidence: str, attachments: List[Path]) -> bool:
        """Differential/metamorphic findings: already adjudicated against the spec by the caller."""
        return self._writeReportAndStore("logicBug", signature, title, evidence, attachments, "adjudicated by spec vote", evidence)

    def _adjudicateAndRecord(self, kind: str, signature: str, origin: str, evidence: str, attachments: List[Path],
                             sanitizerOutput: str) -> bool:
        vote = self.votingPanel.decide(f"crash:{signature[:40]}", promptLibrary.buildCrashAdjudicationQuestion(), evidence)
        if not vote.approved:
            logger.info("Crash %s judged to be a HARNESS/POC MISTAKE (%s); not reported", signature, vote.summarize()[:200])
            logEvent("crashRejected", signature=signature, votes=vote.summarize()[:500])
            return False
        return self._writeReportAndStore(kind, signature, origin, evidence, attachments, vote.summarize(), sanitizerOutput)

    def _writeReportAndStore(self, kind: str, signature: str, origin: str, evidence: str, attachments: List[Path],
                             votesSummary: str, rawOutput: str) -> bool:
        reportDir = self.findingsDir / makeSafeName(signature, 80)
        reportDir.mkdir(parents=True, exist_ok=True)
        for attachment in attachments:
            if attachment and Path(attachment).exists():
                shutil.copy(attachment, reportDir / Path(attachment).name)
        reportPath = reportDir / "report.md"
        reportPath.write_text(
            f"# Candidate finding: {signature}\n\n- Kind: {kind}\n- Origin: {origin}\n- LLM adjudication: {votesSummary}\n\n"
            "## MANUAL CHECKLIST BEFORE CLAIMING THIS AS A NEW BUG\n"
            "1. Reproduce with a STANDALONE C program that uses only documented public API.\n"
            "2. Re-test on the latest upstream master (git pull, rebuild).\n"
            "3. Search the libxml2 issue tracker and CVE list for duplicates.\n"
            "4. Read the documentation of every API in the stack trace; confirm ownership rules are respected.\n\n"
            f"## Evidence\n\n```\n{truncateText(rawOutput, 8000)}\n```\n", encoding="utf-8")
        isNew = self.store.addFinding(kind, signature, origin, str(reportPath), votesSummary)
        if isNew:
            logger.warning("*** NEW CANDIDATE FINDING: %s (report: %s) ***", signature, reportPath)
        return isNew
