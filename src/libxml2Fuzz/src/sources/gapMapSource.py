"""Hypothesis source 1: under-used public API (your original 'harness history' idea)."""
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

from src.core.appConfig import AppConfig
from src.core.appLogger import getLogger, logEvent
from src.core.hypothesisStore import HypothesisStore
from src.infra.coverageAnalyzer import FunctionCoverage
from src.infra.sourceIndexer import SourceIndexer, estimateComplexity

logger = getLogger("gapMap")


@dataclass
class ApiGap:
    functionName: str
    component: str
    upstreamUsageCount: int
    baselineCoverage: float
    complexity: int
    gapScore: float


@dataclass
class ApiComponent:
    name: str
    functionNames: List[str]
    totalGapScore: float


class GapMapSource:
    def __init__(self, config: AppConfig, indexer: SourceIndexer, store: HypothesisStore):
        self.config = config
        self.indexer = indexer
        self.store = store
        self.sourceDir = config.getPath("paths.libxml2Dir")

    def countUpstreamHarnessUsage(self) -> Dict[str, int]:
        """How many times each public function name appears in the upstream fuzz/*.c harnesses."""
        usageCounts: Dict[str, int] = {}
        fuzzDir = self.sourceDir / "fuzz"
        harnessText = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in sorted(fuzzDir.glob("*.c"))) if fuzzDir.exists() else ""
        wordCounts: Dict[str, int] = {}
        for word in re.findall(r"\b[A-Za-z_]\w*\b", harnessText):
            wordCounts[word] = wordCounts.get(word, 0) + 1
        for functionName in self.indexer.getPublicApiNames():
            usageCounts[functionName] = wordCounts.get(functionName, 0)
        logger.info("Scanned upstream harnesses: %d public functions are never mentioned",
                    sum(1 for count in usageCounts.values() if count == 0))
        return usageCounts

    def buildApiGapMap(self, baselineCoverage: Dict[str, FunctionCoverage]) -> List[ApiGap]:
        """Ranks public functions: never used by upstream harnesses + low baseline coverage + complex = high gap score."""
        usageCounts = self.countUpstreamHarnessUsage()
        gaps: List[ApiGap] = []
        for functionName in self.indexer.getPublicApiNames():
            functionInfo = self.indexer.findFunction(functionName)
            if functionInfo is None:
                continue
            complexity = estimateComplexity(functionInfo.sourceText)
            coverageRatio = baselineCoverage[functionName].ratio if functionName in baselineCoverage else 0.0
            usagePenalty = 1.0 if usageCounts.get(functionName, 0) == 0 else 0.4
            gapScore = (1.0 - coverageRatio) * usagePenalty * (1.0 + min(complexity, 60) / 20.0)
            gaps.append(ApiGap(functionName, self.indexer.getComponentOfFunction(functionName),
                               usageCounts.get(functionName, 0), coverageRatio, complexity, gapScore))
        gaps.sort(key=lambda gap: gap.gapScore, reverse=True)
        logEvent("apiGapMapBuilt", functionCount=len(gaps), topFunction=gaps[0].functionName if gaps else "")
        return gaps

    def groupIntoComponents(self, gaps: List[ApiGap], maxApisPerComponent: int) -> List[ApiComponent]:
        """Groups gaps by header file (reader, writer, tree, ...) so each component gets its own harness."""
        gapsByComponent: Dict[str, List[ApiGap]] = {}
        for gap in gaps:
            gapsByComponent.setdefault(gap.component, []).append(gap)
        components = [ApiComponent(name, [gap.functionName for gap in componentGaps[:maxApisPerComponent]],
                                   sum(gap.gapScore for gap in componentGaps[:maxApisPerComponent]))
                      for name, componentGaps in gapsByComponent.items() if name != "internal"]
        components.sort(key=lambda component: component.totalGapScore, reverse=True)
        return components

    def createHypotheses(self, gaps: List[ApiGap]) -> int:
        topCount = self.config.get("discovery.apiGapTopFunctions", 40)
        createdCount = 0
        maxScore = gaps[0].gapScore if gaps else 1.0
        for gap in gaps[:topCount]:
            description = (f"Public function {gap.functionName} (component {gap.component}) is used {gap.upstreamUsageCount}x by "
                           f"upstream harnesses, baseline coverage {gap.baselineCoverage:.0%}, complexity {gap.complexity}. "
                           f"Audit it for bugs reachable only through unusual API usage.")
            hypothesisId = self.store.addHypothesis("apiGap", f"Under-tested API {gap.functionName}", gap.functionName,
                                                    description, bugClass="unknown", priority=0.3 + 0.4 * gap.gapScore / maxScore)
            createdCount += 1 if hypothesisId else 0
        return createdCount
