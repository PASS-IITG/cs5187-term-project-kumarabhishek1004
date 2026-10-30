"""Wires the three engines together: hypotheses -> audit/harness/differential -> fuzzing -> feedback -> triage."""
import time
from typing import Dict, List

from src.core.appConfig import AppConfig
from src.core.appLogger import getLogger, logEvent, logStageBanner
from src.core.hypothesisStore import (HypothesisStore, statusConfirmed, statusDone, statusFailed, statusHandedToHarness,
                                      statusAuditing, statusVotedDown)
from src.core.llmClient import AllProvidersExhaustedError, LlmError, LlmRouter
from src.engines import auditEngine as auditModule
from src.engines.auditEngine import AuditEngine
from src.engines.differentialEngine import DifferentialEngine
from src.engines.harnessEngine import HarnessEngine, HarnessRecord
from src.engines.longFuzzRunner import FuzzScheduler, LongFuzzRunner
from src.infra.baselineFuzzers import BaselineFuzzers
from src.infra.coverageAnalyzer import CoverageAnalyzer, FunctionCoverage
from src.infra.libxmlBuilder import LibxmlBuilder
from src.infra.sourceIndexer import SourceIndexer
from src.sources.commitStreamSource import CommitStreamSource
from src.sources.gapMapSource import GapMapSource
from src.sources.pastFixSource import PastFixSource
from src.sources.staticAnalyzerSource import StaticAnalyzerSource
from src.triage.crashTriage import CrashTriage
from src.triage.llmVoting import VotingPanel

logger = getLogger("orchestrator")


class Orchestrator:
    def __init__(self, config: AppConfig):
        self.config = config
        self.machineIndex = config.get("distribution.machineIndex", 0)
        self.machineCount = config.get("distribution.machineCount", 1)
        self.store = HypothesisStore(config.getPath("paths.databasePath"))
        self.router = LlmRouter(config)
        self.builder = LibxmlBuilder(config)
        self.indexer = SourceIndexer(config.getPath("paths.libxml2Dir"))
        self.coverageAnalyzer = CoverageAnalyzer(config)
        self.votingPanel = VotingPanel(config, self.router)
        self.crashTriage = CrashTriage(config, self.store, self.votingPanel)
        self.baseline = BaselineFuzzers(config, self.builder, self.coverageAnalyzer)
        self.auditEngine = AuditEngine(config, self.router, self.indexer, self.builder, self.votingPanel, self.crashTriage)
        self.harnessEngine = HarnessEngine(config, self.router, self.indexer, self.builder, self.coverageAnalyzer, self.crashTriage)
        self.differentialEngine = DifferentialEngine(config, self.router, self.builder, self.store, self.votingPanel, self.crashTriage)
        self.fuzzRunner = LongFuzzRunner(config)
        self.gapMapSource = GapMapSource(config, self.indexer, self.store)
        self.baselineCoverage: Dict[str, FunctionCoverage] = {}
        self.harnessRecords: List[HarnessRecord] = []

    def runLlmSelfTest(self) -> bool:
        """One tiny request per provider: proves the key, base URL and model ID work before real work starts."""
        providerNames = self.router.getUsableProviderNames()
        if not providerNames:
            logger.error("No LLM provider is configured (set GROQ_API_KEY or edit config/settings.json)")
            return False
        allWorking = True
        for providerName in providerNames:
            try:
                reply = self.router.askText("judge", "You are a connectivity test.", "Reply with exactly the word OK.", 0.0, 400, providerName)
            except LlmError as llmError:
                logger.error("LLM self-test FAILED for %s: %s", providerName, llmError)
                allWorking = False
                continue
            if reply.strip():
                logger.info("LLM self-test OK for %s -> reply: %r", providerName, reply.strip()[:60])
            else:
                logger.warning("LLM self-test for %s returned EMPTY text (reasoning models can spend all tokens thinking). "
                               "If this persists, raise llm.defaultMaxTokens.", providerName)
                allWorking = False
        self.router.logUsageSummary()
        return allWorking

    # ------------------------------------------------------------------ phase A: setup
    def runSetup(self, updateSource: bool = False) -> bool:
        logStageBanner(logger, "A. SETUP (toolchain, source, builds)")
        if not self.builder.checkToolchain():
            logger.error("Fix the missing tools above and re-run 'setup'.")
            return False
        if not self.builder.ensureSourceCheckedOut(updateSource):
            logger.error("Could not obtain libxml2 source")
            return False
        logger.info("libxml2 commit under test: %s", self.builder.getCurrentCommit())
        return self.builder.buildAllEnabledVariants()

    def runBaseline(self, durationHours: float) -> None:
        logStageBanner(logger, "A2. BASELINE (upstream harnesses in the background)")
        self.baseline.startBackgroundFuzzing(durationHours)

    # ------------------------------------------------------------------ phase B: discovery
    def runDiscovery(self) -> None:
        logStageBanner(logger, "B. HYPOTHESIS DISCOVERY (4 sources)")
        enabledSources = self.config.get("discovery.enabledSources", [])
        self.indexer.ensureIndexed()
        sourceRunners = {
            "apiGap": self._runApiGapSource,
            "pastFix": lambda: PastFixSource(self.config, self.router, self.store).mineAllCommits(),
            "commitStream": lambda: CommitStreamSource(self.config, self.router, self.store).reviewNewCommits(),
            "staticAnalyzer": lambda: StaticAnalyzerSource(self.config, self.router, self.store, self.indexer, self.builder).mineWarnings(),
        }
        for sourceName, runSource in sourceRunners.items():
            if sourceName not in enabledSources:
                continue
            try:
                runSource()
            except AllProvidersExhaustedError:
                self._reportProvidersExhausted(f"discovery source '{sourceName}' (other sources continue)")
        logger.info("Hypotheses by source: %s", self.store.countBySource())

    def _runApiGapSource(self) -> None:
        self.baselineCoverage = self.baselineCoverage or self.baseline.measureBaselineCoverage()
        gaps = self.gapMapSource.buildApiGapMap(self.baselineCoverage)
        logger.info("apiGap source created %d hypotheses", self.gapMapSource.createHypotheses(gaps))

    def installReferenceHarness(self) -> None:
        record = self.harnessEngine.installReferenceHarness()
        if record:
            self.harnessRecords.append(record)

    def retryFailedHypotheses(self) -> None:
        self.store.resetRetryableHypotheses()
        logger.info("Hypotheses by status: %s", self.store.countByStatus())

    # ------------------------------------------------------------------ Engine 1
    def runAuditLoop(self) -> None:
        logStageBanner(logger, "C1. ENGINE 1: LLM AUDIT -> VOTE -> PoC -> SANITIZER")
        limit = self.config.get("audit.maxHypothesesPerRun", 30)
        for hypothesis in self.store.getNextPending(limit, self.machineIndex, self.machineCount):
            self.store.updateStatus(hypothesis.id, statusAuditing)
            try:
                outcome = self.auditEngine.auditHypothesis(hypothesis)
            except AllProvidersExhaustedError:
                self.store.updateStatus(hypothesis.id, "pending", "LLM providers exhausted; retry later")
                self._reportProvidersExhausted("audit loop")
                return
            logEvent("auditOutcome", hypothesisId=hypothesis.id, outcome=outcome.kind)
            if outcome.kind == auditModule.outcomeConfirmed:
                self.store.updateStatus(hypothesis.id, statusConfirmed, outcome.note)
            elif outcome.kind == auditModule.outcomeNotTriggered:
                self._handToHarnessEngine(hypothesis, outcome.note)
            elif outcome.kind == auditModule.outcomeVotedDown:
                self.store.updateStatus(hypothesis.id, statusVotedDown, outcome.note)
            elif outcome.kind == auditModule.outcomeError:
                self.store.updateStatus(hypothesis.id, statusFailed, outcome.note)
            else:
                self.store.updateStatus(hypothesis.id, statusDone, f"{outcome.kind}: {outcome.note}")

    def _handToHarnessEngine(self, hypothesis, note: str) -> None:
        """Interconnection 1: plausible suspicion without a PoC -> targeted fuzz harness (Engine 3)."""
        logger.info("Hypothesis #%d is plausible but no PoC triggered it -> generating a TARGETED FUZZ HARNESS", hypothesis.id)
        try:
            record = self.harnessEngine.createHarnessForHypothesis(hypothesis)
        except AllProvidersExhaustedError:
            self.store.updateStatus(hypothesis.id, "pending", "LLM providers exhausted; retry later")
            self._reportProvidersExhausted("targeted harness generation")
            return
        if record:
            self.harnessRecords.append(record)
        self.store.updateStatus(hypothesis.id, statusHandedToHarness, f"{note}; harness={'created' if record else 'failed'}")

    # ------------------------------------------------------------------ Engine 3
    def runHarnessGeneration(self) -> None:
        logStageBanner(logger, "C3. ENGINE 3: API-GAP HARNESS GENERATION")
        self.indexer.ensureIndexed()
        self.baselineCoverage = self.baselineCoverage or self.baseline.measureBaselineCoverage()
        gaps = self.gapMapSource.buildApiGapMap(self.baselineCoverage)
        components = self.gapMapSource.groupIntoComponents(gaps, self.config.get("harness.maxApisPerComponent", 25))
        myComponents = [component for index, component in enumerate(components) if index % self.machineCount == self.machineIndex]
        for component in myComponents[: self.config.get("harness.componentsPerRun", 6)]:
            try:
                record = self.harnessEngine.createHarnessForComponent(component.name, component.functionNames)
            except AllProvidersExhaustedError:
                self._reportProvidersExhausted("harness generation")
                return
            if record:
                self.harnessRecords.append(record)

    def runFuzzCampaign(self, totalHours: float) -> None:
        logStageBanner(logger, f"D. LONG FUZZING ({totalHours}h budget)")
        knownNames = {record.name for record in self.harnessRecords}
        self.harnessRecords += [record for record in self.harnessEngine.loadExistingHarnesses() if record.name not in knownNames]
        if not self.harnessRecords:
            logger.error("No validated harnesses to fuzz. Run 'harness' (and/or 'audit') first.")
            return
        recordsByName = {record.name: record for record in self.harnessRecords}
        scheduler = FuzzScheduler(list(recordsByName), self.config.get("fuzzing.explorationRate", 0.2),
                                  self.config.get("fuzzing.plateauSeconds", 3600),
                                  int(self.config.get("fuzzing.totalBudgetHoursPerHarness", 4) * 3600))
        deadline = time.time() + totalHours * 3600
        while time.time() < deadline:
            harnessName = scheduler.chooseNext()
            if harnessName is None:
                logger.info("All harnesses retired (plateau or budget). Ending fuzz campaign early.")
                break
            record = recordsByName[harnessName]
            chunkSeconds = int(min(self.config.get("fuzzing.chunkSeconds", 900), max(30, deadline - time.time())))
            chunkResult = self.fuzzRunner.runChunk(record, chunkSeconds)
            if chunkResult.newCrashFiles:
                logger.warning("%d crash artifacts in '%s' -> triage", len(chunkResult.newCrashFiles), harnessName)
                self.crashTriage.processFuzzCrashes(harnessName, record.binaryPath, record.sourcePath, chunkResult.newCrashFiles)
                self.fuzzRunner.markCrashesProcessed(record, chunkResult.newCrashFiles)
            scheduler.reportChunk(harnessName, chunkSeconds, chunkResult.coverage)
        self._deriveHypothesesFromCoverage()

    def _deriveHypothesesFromCoverage(self) -> None:
        """Interconnection 2: functions the fuzzers still barely reach become new audit hypotheses for Engine 1."""
        logger.info("Feedback: turning remaining coverage gaps into new hypotheses for Engine 1")
        for record in self.harnessRecords:
            coverageByName, _ = self.harnessEngine.measureCoverage(record)
            for functionName in record.targetFunctions:
                ratio = coverageByName[functionName].ratio if functionName in coverageByName else 0.0
                if ratio < 0.3:
                    self.store.addHypothesis("harnessCoverageGap", f"Hard-to-reach {functionName} ({record.name})", functionName,
                                             f"Harness {record.name} reaches only {ratio:.0%} of {functionName} after long fuzzing; "
                                             "the unreached branches may hide bugs or need special inputs.", priority=0.6)

    # ------------------------------------------------------------------ Engine 2
    def runDifferentialTesting(self) -> None:
        logStageBanner(logger, "C2. ENGINE 2: DIFFERENTIAL / METAMORPHIC TESTING")
        try:
            self.differentialEngine.runCampaign()
        except AllProvidersExhaustedError:
            self._reportProvidersExhausted("differential testing")

    # ------------------------------------------------------------------ everything
    def runAll(self, fuzzHours: float, cycles: int = 2) -> None:
        if not self.runSetup():
            return
        self.runBaseline(durationHours=fuzzHours * cycles + 1)
        self.runDiscovery()
        for cycleNumber in range(1, cycles + 1):
            logStageBanner(logger, f"CYCLE {cycleNumber}/{cycles}")
            self.runAuditLoop()
            self.runDifferentialTesting()
            self.runHarnessGeneration()
            self.runFuzzCampaign(fuzzHours)
            self._processBaselineCrashes()
            self.printStatus()
        self.baseline.stopBackgroundFuzzing()

    def _processBaselineCrashes(self) -> None:
        crashes = self.baseline.collectBaselineCrashes()
        if crashes:
            logger.warning("%d crash artifacts found by upstream baseline harnesses (re-test on latest master before claiming)", len(crashes))

    def _reportProvidersExhausted(self, phaseName: str) -> None:
        logger.critical("ALL LLM PROVIDERS ARE EXHAUSTED during '%s'. Pending work is kept in the database. "
                        "Add credit/keys or wait for the rate limit, then re-run the same command.", phaseName)
        self.router.logUsageSummary()

    def printStatus(self) -> None:
        logStageBanner(logger, "STATUS")
        logger.info("Hypotheses by status: %s", self.store.countByStatus())
        logger.info("Hypotheses by source: %s", self.store.countBySource())
        findings = self.store.listFindings()
        logger.info("Candidate findings: %d", len(findings))
        for finding in findings:
            logger.info("  [%s] %s -> %s", finding["kind"], finding["signature"], finding["reportPath"])
        self.router.logUsageSummary()
