"""Engine 2: differential and metamorphic testing of libxml2 with LLM-generated tricky XML."""
import xml.parsers.expat
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from src.core.appConfig import AppConfig, templatesDir
from src.core.appLogger import getLogger, logEvent
from src.core.hypothesisStore import HypothesisStore
from src.core.llmClient import AllProvidersExhaustedError, LlmError, LlmRouter
from src.core.shellRunner import runCommand
from src.core.textUtils import makeSafeName, tailLines
from src.infra.libxmlBuilder import LibxmlBuilder
from src.prompts import promptLibrary
from src.triage.crashTriage import CrashTriage, containsSanitizerFailure
from src.triage.llmVoting import VotingPanel

logger = getLogger("differential")


@dataclass
class Disagreement:
    kind: str
    details: str


class DifferentialEngine:
    def __init__(self, config: AppConfig, router: LlmRouter, builder: LibxmlBuilder, store: HypothesisStore,
                 votingPanel: VotingPanel, crashTriage: CrashTriage):
        self.config = config
        self.router = router
        self.builder = builder
        self.store = store
        self.votingPanel = votingPanel
        self.crashTriage = crashTriage
        self.workDir = config.getPath("paths.workDir") / "differential"
        self.oracleBinary = self.workDir / "oracleRunner"
        self.chunkSizes = config.get("differential.pushChunkSizes", [1, 7])

    def prepareOracle(self) -> bool:
        self.workDir.mkdir(parents=True, exist_ok=True)
        result = self.builder.compileStandaloneProgram("asanUbsan", templatesDir / "oracleRunner.cc", self.oracleBinary)
        if not result.succeeded:
            logger.error("Could not build the differential oracle: %s", tailLines(result.stderr, 10))
        return result.succeeded

    # ------------------------------------------------------------------ oracles
    def runLibxmlOracle(self, inputPath: Path) -> Dict[str, str]:
        result = runCommand([str(self.oracleBinary), str(inputPath), ",".join(str(size) for size in self.chunkSizes)],
                            timeoutSeconds=self.config.get("differential.oracleTimeoutSeconds", 15),
                            envOverrides={"ASAN_OPTIONS": "detect_leaks=1:symbolize=1"}, logFailures=False)
        observed: Dict[str, str] = {"returnCode": str(result.returnCode), "timedOut": str(result.timedOut)}
        if containsSanitizerFailure(result.combinedOutput):
            observed["sanitizerReport"] = result.combinedOutput
        for line in result.stdout.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                observed[key.strip()] = value.strip()
        return observed

    @staticmethod
    def runExpatOracle(xmlBytes: bytes) -> bool:
        parser = xml.parsers.expat.ParserCreate()
        try:
            parser.Parse(xmlBytes, True)
            return True
        except xml.parsers.expat.ExpatError:
            return False

    def findDisagreements(self, xmlBytes: bytes, observed: Dict[str, str]) -> List[Disagreement]:
        disagreements: List[Disagreement] = []
        if "sanitizerReport" in observed:
            disagreements.append(Disagreement("oracleSanitizerFailure", observed["sanitizerReport"][:3000]))
        if observed.get("timedOut") == "True":
            disagreements.append(Disagreement("oracleTimeout", "libxml2 oracle exceeded the time limit"))
        if "oneShotWellFormed" not in observed:
            return disagreements
        libxmlWellFormed = observed["oneShotWellFormed"] == "1"
        if libxmlWellFormed != self.runExpatOracle(xmlBytes):
            disagreements.append(Disagreement("wellFormednessVsExpat", f"libxml2 wellFormed={libxmlWellFormed}, expat says the opposite"))
        if libxmlWellFormed and observed.get("roundTripStable") == "0":
            disagreements.append(Disagreement("roundTripUnstable", "parse->serialize->parse->serialize changed the output"))
        for chunkSize in self.chunkSizes:
            if observed.get(f"pushChunk{chunkSize}WellFormed") != observed["oneShotWellFormed"]:
                disagreements.append(Disagreement("pushVsOneShotVerdict", f"chunk size {chunkSize}: push verdict differs from one-shot"))
            elif observed.get(f"pushChunk{chunkSize}SameOutput") == "0":
                disagreements.append(Disagreement("pushVsOneShotOutput", f"chunk size {chunkSize}: push output differs from one-shot"))
        if observed.get("readerWellFormed") != observed["oneShotWellFormed"]:
            disagreements.append(Disagreement("readerVsDomVerdict", "xmlreader verdict differs from DOM parser verdict"))
        return disagreements

    # ------------------------------------------------------------------ campaign
    def generateInputs(self, category: str) -> List[Dict]:
        count = self.config.get("differential.inputsPerCategory", 12)
        try:
            reply = self.router.askJson("generator", promptLibrary.systemSecurityResearcher,
                                        promptLibrary.buildTrickyXmlPrompt(category, count), temperature=0.8, maxTokens=6000)
        except AllProvidersExhaustedError:
            raise
        except LlmError as llmError:
            logger.error("Could not generate inputs for category '%s': %s", category, llmError)
            return []
        return [item for item in reply if isinstance(item, dict) and "xml" in item] if isinstance(reply, list) else []

    def runCampaign(self) -> int:
        if not self.prepareOracle():
            return 0
        confirmedCount = 0
        for category in self.config.get("differential.categories", []):
            inputs = self.generateInputs(category)
            logger.info("Differential category '%s': %d generated inputs", category, len(inputs))
            for index, item in enumerate(inputs):
                inputPath = self.workDir / f"{makeSafeName(category)}_{index}.xml"
                xmlBytes = str(item["xml"]).encode("utf-8", errors="replace")
                inputPath.write_bytes(xmlBytes)
                observed = self.runLibxmlOracle(inputPath)
                logEvent("differentialRun", category=category, input=inputPath.name)
                for disagreement in self.findDisagreements(xmlBytes, observed):
                    confirmedCount += 1 if self._handleDisagreement(category, inputPath, xmlBytes, disagreement, observed) else 0
        logger.info("Differential campaign finished: %d candidate findings", confirmedCount)
        return confirmedCount

    def _handleDisagreement(self, category: str, inputPath: Path, xmlBytes: bytes, disagreement: Disagreement, observed: Dict) -> bool:
        logger.warning("DISAGREEMENT [%s] on %s: %s", disagreement.kind, inputPath.name, disagreement.details[:150])
        logEvent("disagreementFound", kind=disagreement.kind, input=inputPath.name)
        signature = f"diff__{disagreement.kind}__{makeSafeName(inputPath.stem)}"
        if disagreement.kind == "oracleSanitizerFailure":
            return self.crashTriage.recordLogicCandidate(signature, f"Sanitizer failure on {inputPath.name}", disagreement.details, [inputPath])
        evidence = f"Check: {disagreement.kind}\nDetails: {disagreement.details}\nRaw observations: {observed}"
        vote = self.votingPanel.decide(f"spec:{signature[:40]}",
                                       "Based on the XML 1.0 / Namespaces specs, is libxml2's observed behavior a genuine spec violation or inconsistency (not a deliberate documented design choice)?",
                                       f"Input:\n{xmlBytes.decode('utf-8', errors='replace')}\n\n{evidence}")
        if not vote.approved:
            return False
        # Interconnection: a confirmed disagreement also becomes a hypothesis for the Engine 1 root-cause audit.
        self.store.addHypothesis("differential", f"{disagreement.kind} on {inputPath.name}", self._guessFunctionForKind(disagreement.kind),
                                 f"Differential disagreement {disagreement.kind}: {disagreement.details[:300]}", priority=0.85)
        return self.crashTriage.recordLogicCandidate(signature, f"{disagreement.kind} on {inputPath.name}",
                                                     evidence + "\n\nVOTES: " + vote.summarize(), [inputPath])

    @staticmethod
    def _guessFunctionForKind(kind: str) -> str:
        return {"pushVsOneShotVerdict": "xmlParseChunk", "pushVsOneShotOutput": "xmlParseChunk", "readerVsDomVerdict": "xmlTextReaderRead",
                "roundTripUnstable": "xmlDocDumpMemory"}.get(kind, "xmlParseDocument")
