"""Hypothesis source 4: Clang static analyzer warnings, triaged by the LLM for reachability."""
import re
from typing import Dict, List

from src.core.appConfig import AppConfig
from src.core.appLogger import getLogger
from src.core.hypothesisStore import HypothesisStore
from src.core.llmClient import AllProvidersExhaustedError, LlmError, LlmRouter
from src.core.shellRunner import runCommand
from src.infra.libxmlBuilder import LibxmlBuilder
from src.infra.sourceIndexer import SourceIndexer
from src.core.textUtils import truncateText
from src.prompts import promptLibrary

logger = getLogger("staticAnalyzer")
warningPattern = re.compile(r"^(.+?):(\d+):(\d+): warning: (.+?)(?: \[(.+)\])?$")


class StaticAnalyzerSource:
    def __init__(self, config: AppConfig, router: LlmRouter, store: HypothesisStore, indexer: SourceIndexer,
                 builder: LibxmlBuilder):
        self.config = config
        self.router = router
        self.store = store
        self.indexer = indexer
        self.builder = builder

    def runAnalyzerOnAllFiles(self) -> List[Dict[str, str]]:
        includeFlags = self.builder.getIncludeFlags("asanUbsan")
        warnings: List[Dict[str, str]] = []
        for sourceFile in self.indexer.listSourceFiles():
            result = runCommand([self.config.get("toolchain.cCompiler", "clang"), "--analyze", "-Xclang",
                                 "-analyzer-output=text"] + includeFlags + [str(sourceFile)],
                                timeoutSeconds=300, logFailures=False)
            for line in result.stderr.splitlines():
                match = warningPattern.match(line)
                if match:
                    warnings.append({"filePath": match.group(1), "line": match.group(2), "message": match.group(4),
                                     "checker": match.group(5) or ""})
        logger.info("Static analyzer produced %d warnings", len(warnings))
        return warnings

    def triageWarnings(self, warnings: List[Dict[str, str]]) -> int:
        createdCount = 0
        for warning in warnings[: self.config.get("discovery.staticAnalyzerMaxWarnings", 30)]:
            functionInfo = self.indexer.findEnclosingFunction(warning["filePath"], int(warning["line"]))
            if functionInfo is None:
                continue
            warningText = f"{warning['filePath']}:{warning['line']}: {warning['message']} [{warning['checker']}]"
            try:
                verdict = self.router.askJson("analyst", promptLibrary.systemSecurityResearcher,
                                              promptLibrary.buildStaticWarningTriagePrompt(
                                                  warningText, truncateText(functionInfo.sourceText, 6000)))
            except AllProvidersExhaustedError:
                raise
            except LlmError as llmError:
                logger.error("Static warning triage failed: %s", llmError)
                continue
            if verdict.get("isLikelyReal"):
                hypothesisId = self.store.addHypothesis(
                    "staticAnalyzer", f"Analyzer: {warning['message'][:70]}", functionInfo.name,
                    f"{warningText}. LLM reasoning: {verdict.get('reasoning', '')}", filePath=warning["filePath"],
                    bugClass=verdict.get("bugClass", "unknown"), priority=0.45 + 0.4 * float(verdict.get("confidence", 0.5)))
                createdCount += 1 if hypothesisId else 0
        return createdCount

    def mineWarnings(self) -> int:
        return self.triageWarnings(self.runAnalyzerOnAllFiles())
