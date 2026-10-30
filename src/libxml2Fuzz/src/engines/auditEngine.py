"""Engine 1: LLM code audit -> vote -> proof-of-concept -> sanitizer verdict."""
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from src.core.appConfig import AppConfig
from src.core.appLogger import getLogger, logEvent
from src.core.hypothesisStore import Hypothesis
from src.core.llmClient import AllProvidersExhaustedError, LlmError, LlmRouter
from src.core.shellRunner import runCommand
from src.core.textUtils import extractCodeBlock, makeSafeName, tailLines, truncateText
from src.infra.libxmlBuilder import LibxmlBuilder
from src.infra.sourceIndexer import SourceIndexer
from src.prompts import promptLibrary
from src.triage.crashTriage import CrashTriage, containsSanitizerFailure
from src.triage.llmVoting import VotingPanel

logger = getLogger("audit")

outcomeNoSuspicion = "noSuspicion"
outcomeVotedDown = "votedDown"
outcomeConfirmed = "pocConfirmed"
outcomeRejectedAsMisuse = "pocRejectedAsMisuse"
outcomeNotTriggered = "pocNotTriggered"
outcomeError = "error"


@dataclass
class AuditOutcome:
    kind: str
    note: str = ""
    suspicionSummary: str = ""


class AuditEngine:
    def __init__(self, config: AppConfig, router: LlmRouter, indexer: SourceIndexer, builder: LibxmlBuilder,
                 votingPanel: VotingPanel, crashTriage: CrashTriage):
        self.config = config
        self.router = router
        self.indexer = indexer
        self.builder = builder
        self.votingPanel = votingPanel
        self.crashTriage = crashTriage
        self.auditDir = config.getPath("paths.workDir") / "audit"
        self.maxPocAttempts = config.get("audit.maxPocAttempts", 3)

    def auditHypothesis(self, hypothesis: Hypothesis) -> AuditOutcome:
        logger.info("---- AUDIT hypothesis #%d [%s] %s", hypothesis.id, hypothesis.source, hypothesis.title)
        try:
            return self._runAuditPipeline(hypothesis)
        except AllProvidersExhaustedError:
            raise
        except LlmError as llmError:
            logger.error("Audit of #%d aborted by LLM failure: %s", hypothesis.id, llmError)
            return AuditOutcome(outcomeError, str(llmError))

    def _runAuditPipeline(self, hypothesis: Hypothesis) -> AuditOutcome:
        functionInfo = self.indexer.findFunction(hypothesis.functionName)
        if functionInfo is None:
            logger.warning("Function '%s' not found in source index; hypothesis #%d cannot be audited", hypothesis.functionName, hypothesis.id)
            return AuditOutcome(outcomeError, "function not found in source index")
        functionSource = truncateText(functionInfo.sourceText, self.config.get("audit.maxFunctionSourceChars", 9000))
        declaration = self.indexer.getHeaderDeclaration(hypothesis.functionName)

        suspicion = self.generateSuspicion(hypothesis, functionSource, declaration)
        if not suspicion.get("isPlausible"):
            logger.info("LLM sees no plausible bug in %s (#%d)", hypothesis.functionName, hypothesis.id)
            logEvent("suspicionRejectedByAuditor", hypothesisId=hypothesis.id)
            return AuditOutcome(outcomeNoSuspicion, suspicion.get("reasoning", ""))
        suspicionSummary = f"{suspicion.get('bugClass')}: {suspicion.get('triggerScenario')}"
        logEvent("suspicionGenerated", hypothesisId=hypothesis.id, bugClass=suspicion.get("bugClass"))

        vote = self.votingPanel.decide(f"suspicion#{hypothesis.id}", promptLibrary.buildVoteQuestionForSuspicion(),
                                       f"FUNCTION:\n{functionSource}\n\nSUSPICION:\n{suspicion}")
        if not vote.approved:
            return AuditOutcome(outcomeVotedDown, vote.summarize(), suspicionSummary)

        return self.tryProofOfConcept(hypothesis, suspicion, functionSource, declaration, suspicionSummary)

    def generateSuspicion(self, hypothesis: Hypothesis, functionSource: str, declaration: str) -> dict:
        callers = self.indexer.findCallerFunctions(hypothesis.functionName, self.config.get("audit.maxCallersInContext", 5))
        callerText = "\n\n".join(truncateText(caller.sourceText, 1500) for caller in callers)
        reply = self.router.askJson("auditor", promptLibrary.systemSecurityResearcher,
                                    promptLibrary.buildSuspicionPrompt(functionSource, declaration, callerText, hypothesis.description),
                                    temperature=0.3)
        return reply if isinstance(reply, dict) else {"isPlausible": False}

    def tryProofOfConcept(self, hypothesis: Hypothesis, suspicion: dict, functionSource: str, declaration: str,
                          suspicionSummary: str) -> AuditOutcome:
        pocDir = self.auditDir / f"h{hypothesis.id}_{makeSafeName(hypothesis.functionName)}"
        pocDir.mkdir(parents=True, exist_ok=True)
        pocCode = self._askForCode(promptLibrary.buildPocPrompt(suspicion, functionSource, declaration))
        for attemptNumber in range(1, self.maxPocAttempts + 1):
            if not pocCode:
                return AuditOutcome(outcomeError, "LLM returned no code block", suspicionSummary)
            pocPath = pocDir / f"poc_attempt{attemptNumber}.c"
            pocPath.write_text(pocCode, encoding="utf-8")
            compileResult = self.builder.compileStandaloneProgram("asanUbsan", pocPath, pocDir / f"poc_attempt{attemptNumber}")
            if not compileResult.succeeded:
                logger.info("PoC attempt %d did not compile; asking LLM to repair", attemptNumber)
                logEvent("pocCompileFailed", hypothesisId=hypothesis.id, attempt=attemptNumber)
                pocCode = self._askForCode(promptLibrary.buildPocRepairPrompt(pocCode, "compile error", tailLines(compileResult.stderr, 25)))
                continue
            runResult = runCommand([str(pocDir / f"poc_attempt{attemptNumber}")], timeoutSeconds=self.config.get("audit.pocRunTimeoutSeconds", 30),
                                   envOverrides={"ASAN_OPTIONS": "detect_leaks=1:symbolize=1", "UBSAN_OPTIONS": "print_stacktrace=1"},
                                   logFailures=False)
            if containsSanitizerFailure(runResult.combinedOutput) or runResult.timedOut:
                logger.warning("PoC attempt %d TRIGGERED a sanitizer report for hypothesis #%d", attemptNumber, hypothesis.id)
                logEvent("pocTriggered", hypothesisId=hypothesis.id, attempt=attemptNumber, timedOut=runResult.timedOut)
                isNew = self.crashTriage.processPocFinding(hypothesis.id, hypothesis.title, pocPath,
                                                           runResult.combinedOutput or "timeout / hang", suspicionSummary)
                return AuditOutcome(outcomeConfirmed if isNew else outcomeRejectedAsMisuse, "sanitizer triggered", suspicionSummary)
            logger.info("PoC attempt %d ran clean (exit %d); asking LLM to try a different trigger", attemptNumber, runResult.returnCode)
            logEvent("pocRanClean", hypothesisId=hypothesis.id, attempt=attemptNumber)
            pocCode = self._askForCode(promptLibrary.buildPocRepairPrompt(pocCode, "ran without any sanitizer report", tailLines(runResult.combinedOutput, 15) or "(no output)"))
        return AuditOutcome(outcomeNotTriggered, f"no sanitizer report after {self.maxPocAttempts} attempts", suspicionSummary)

    def _askForCode(self, prompt: str) -> Optional[str]:
        reply = self.router.askText("generator", promptLibrary.systemCodeWriter, prompt, temperature=0.3, maxTokens=6000)
        return extractCodeBlock(reply, ["c", "cpp", "c++"])
