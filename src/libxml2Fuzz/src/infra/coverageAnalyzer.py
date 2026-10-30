"""Collects llvm-cov coverage for harnesses and answers 'which functions/branches are still uncovered?'."""
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from src.core.appConfig import AppConfig
from src.core.appLogger import getLogger
from src.core.shellRunner import runCommand
from src.core.textUtils import tailLines, truncateText

logger = getLogger("coverage")


@dataclass
class FunctionCoverage:
    name: str
    executionCount: int
    coveredRegions: int
    totalRegions: int

    @property
    def ratio(self) -> float:
        return self.coveredRegions / self.totalRegions if self.totalRegions else 0.0


class CoverageAnalyzer:
    def __init__(self, config: AppConfig):
        self.config = config
        self.profdataTool = config.get("toolchain.llvmProfdata", "llvm-profdata")
        self.covTool = config.get("toolchain.llvmCov", "llvm-cov")

    def generateProfile(self, coverageBinary: Path, corpusDirs: List[Path], outputDir: Path,
                        timeoutSeconds: int = 900) -> Optional[Path]:
        """Replays the corpus through the coverage binary and merges the raw profile."""
        outputDir.mkdir(parents=True, exist_ok=True)
        for oldFile in outputDir.glob("*.profraw"):
            oldFile.unlink()
        existingCorpora = [str(path) for path in corpusDirs if path.exists()]
        runResult = runCommand([str(coverageBinary)] + existingCorpora + ["-runs=0", "-timeout=20"],
                               envOverrides={"LLVM_PROFILE_FILE": str(outputDir / "run-%p.profraw")},
                               timeoutSeconds=timeoutSeconds, logFailures=False)
        rawProfiles = sorted(outputDir.glob("*.profraw"))
        if not rawProfiles:
            logger.error("No .profraw produced by %s (exit %s): %s", coverageBinary.name, runResult.returnCode,
                         tailLines(runResult.combinedOutput, 8))
            return None
        profdataPath = outputDir / "merged.profdata"
        mergeResult = runCommand([self.profdataTool, "merge", "-sparse"] + [str(path) for path in rawProfiles]
                                 + ["-o", str(profdataPath)], timeoutSeconds=300)
        return profdataPath if mergeResult.succeeded else None

    def exportFunctionCoverage(self, coverageBinary: Path, profdataPath: Path) -> Dict[str, FunctionCoverage]:
        """Per-function covered/total region counts parsed from 'llvm-cov export'."""
        exportResult = runCommand([self.covTool, "export", str(coverageBinary), f"-instr-profile={profdataPath}",
                                   "-skip-expansions"], timeoutSeconds=600, logFailures=True)
        if not exportResult.succeeded:
            return {}
        try:
            exportedData = json.loads(exportResult.stdout)["data"][0]["functions"]
        except (ValueError, KeyError, IndexError) as parseError:
            logger.error("Could not parse llvm-cov export output: %s", parseError)
            return {}
        coverageByName: Dict[str, FunctionCoverage] = {}
        for functionEntry in exportedData:
            shortName = functionEntry["name"].split(":")[-1]
            codeRegions = [region for region in functionEntry["regions"] if region[7] == 0]
            coveredCount = sum(1 for region in codeRegions if region[4] > 0)
            existing = coverageByName.get(shortName)
            if existing is None or coveredCount > existing.coveredRegions:
                coverageByName[shortName] = FunctionCoverage(shortName, functionEntry["count"], coveredCount, len(codeRegions))
        logger.info("Exported coverage for %d functions", len(coverageByName))
        return coverageByName

    def measureFunctions(self, coverageBinary: Path, corpusDirs: List[Path], workDir: Path) -> Dict[str, FunctionCoverage]:
        profdataPath = self.generateProfile(coverageBinary, corpusDirs, workDir)
        if profdataPath is None:
            return {}
        return self.exportFunctionCoverage(coverageBinary, profdataPath)

    def showUncoveredSource(self, coverageBinary: Path, profdataPath: Path, functionName: str, maxChars: int) -> str:
        """Annotated source of one function, keeping only lines that were never executed (count 0)."""
        showResult = runCommand([self.covTool, "show", str(coverageBinary), f"-instr-profile={profdataPath}",
                                 f"-name={functionName}", "-show-line-counts", "-use-color=false"],
                                timeoutSeconds=120, logFailures=False)
        if not showResult.succeeded:
            return ""
        uncoveredLines = [line for line in showResult.stdout.splitlines()
                          if re.match(r"^\s*\d+\|\s*0\|", line)]
        return truncateText("\n".join(uncoveredLines), maxChars)

    @staticmethod
    def computeAverageRatio(coverageByName: Dict[str, FunctionCoverage], functionNames: List[str]) -> float:
        ratios = [coverageByName[name].ratio if name in coverageByName else 0.0 for name in functionNames]
        return sum(ratios) / len(ratios) if ratios else 0.0
