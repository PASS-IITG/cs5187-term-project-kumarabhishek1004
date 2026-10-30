"""Lightweight source navigation for libxml2: function extraction, callers, public API list, header declarations."""
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set

from src.core.appLogger import getLogger

logger = getLogger("indexer")

cKeywords = {"if", "while", "for", "switch", "return", "sizeof", "defined", "else", "do", "case"}
excludedSourceFiles = {"testapi.c", "runtest.c", "runxmlconf.c", "runsuite.c", "testrecurse.c", "testchar.c",
                       "testdict.c", "testlimits.c", "testparser.c", "testModule.c", "testThreads.c"}
functionNameAtLineStart = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*\(")
inlineDefinition = re.compile(r"^[A-Za-z_][\w\s\*]*?\b([A-Za-z_]\w*)\s*\([^;]*$")
publicDeclaration = re.compile(r"XMLPUBFUN\s+[^;]*?\b(\w+)\s*\([^;]*\)[^;]*;")
stringLiteral = re.compile(r'"(\\.|[^"\\])*"|\'(\\.|[^\'\\])*\'')


@dataclass
class FunctionInfo:
    name: str
    filePath: str
    startLine: int
    endLine: int
    sourceText: str

    @property
    def lineCount(self) -> int:
        return self.endLine - self.startLine + 1


def countBraceDelta(line: str) -> int:
    cleaned = stringLiteral.sub('""', line)
    cleaned = re.sub(r"//.*", "", cleaned)
    cleaned = re.sub(r"/\*.*?\*/", "", cleaned)
    return cleaned.count("{") - cleaned.count("}")


def estimateComplexity(sourceText: str) -> int:
    """Rough cyclomatic complexity: number of branching tokens."""
    return len(re.findall(r"\b(if|for|while|case|switch)\b|&&|\|\||\?", sourceText))


class SourceIndexer:
    def __init__(self, sourceDir: Path):
        self.sourceDir = Path(sourceDir)
        self.functionsByName: Dict[str, List[FunctionInfo]] = {}
        self.functionsByFile: Dict[str, List[FunctionInfo]] = {}
        self.publicApi: Dict[str, str] = {}
        self.isIndexed = False

    def listSourceFiles(self) -> List[Path]:
        return sorted(path for path in self.sourceDir.glob("*.c") if path.name not in excludedSourceFiles)

    def ensureIndexed(self) -> None:
        if self.isIndexed:
            return
        for sourceFile in self.listSourceFiles():
            for functionInfo in self.extractFunctions(sourceFile):
                self.functionsByName.setdefault(functionInfo.name, []).append(functionInfo)
                self.functionsByFile.setdefault(str(sourceFile), []).append(functionInfo)
        self._loadPublicApi()
        self.isIndexed = True
        logger.info("Indexed %d functions and %d public API declarations from %s",
                    len(self.functionsByName), len(self.publicApi), self.sourceDir)

    def extractFunctions(self, sourceFile: Path) -> List[FunctionInfo]:
        lines = sourceFile.read_text(encoding="utf-8", errors="replace").splitlines()
        functions: List[FunctionInfo] = []
        lineIndex = 0
        while lineIndex < len(lines):
            functionName = self._matchFunctionStart(lines[lineIndex])
            if functionName is None:
                lineIndex += 1
                continue
            braceLineIndex = self._findOpeningBrace(lines, lineIndex)
            if braceLineIndex is None:
                lineIndex += 1
                continue
            endLineIndex = self._findClosingBrace(lines, braceLineIndex)
            if endLineIndex is None:
                lineIndex += 1
                continue
            sourceStart = max(0, lineIndex - 1) if not lines[lineIndex - 1].strip().endswith((";", "}", "*/")) and lineIndex > 0 else lineIndex
            functions.append(FunctionInfo(functionName, str(sourceFile), sourceStart + 1, endLineIndex + 1,
                                          "\n".join(lines[sourceStart:endLineIndex + 1])))
            lineIndex = endLineIndex + 1
        return functions

    def _matchFunctionStart(self, line: str) -> Optional[str]:
        if not line or line[0] in " \t#/*}{":
            return None
        startMatch = functionNameAtLineStart.match(line)
        if startMatch and startMatch.group(1) not in cKeywords:
            return startMatch.group(1)
        inlineMatch = inlineDefinition.match(line)
        if inlineMatch and inlineMatch.group(1) not in cKeywords and not line.rstrip().endswith(";"):
            return inlineMatch.group(1)
        return None

    def _findOpeningBrace(self, lines: List[str], startIndex: int) -> Optional[int]:
        for index in range(startIndex, min(startIndex + 40, len(lines))):
            if lines[index].rstrip().endswith(";"):
                return None
            if "{" in lines[index]:
                return index
        return None

    def _findClosingBrace(self, lines: List[str], braceLineIndex: int) -> Optional[int]:
        depth = 0
        for index in range(braceLineIndex, len(lines)):
            depth += countBraceDelta(lines[index])
            if depth <= 0 and index >= braceLineIndex:
                return index
        return None

    def _loadPublicApi(self) -> None:
        for headerFile in sorted((self.sourceDir / "include" / "libxml").glob("*.h")):
            headerText = headerFile.read_text(encoding="utf-8", errors="replace")
            for match in publicDeclaration.finditer(headerText):
                declaration = re.sub(r"\s+", " ", match.group(0))
                self.publicApi[match.group(1)] = f"{headerFile.name}: {declaration}"

    # ------------------------------------------------------------------ queries
    def findFunction(self, functionName: str) -> Optional[FunctionInfo]:
        self.ensureIndexed()
        matches = self.functionsByName.get(functionName)
        return matches[0] if matches else None

    def getPublicApiNames(self) -> Set[str]:
        self.ensureIndexed()
        return set(self.publicApi.keys())

    def getHeaderDeclaration(self, functionName: str) -> str:
        self.ensureIndexed()
        return self.publicApi.get(functionName, "")

    def getComponentOfFunction(self, functionName: str) -> str:
        declaration = self.getHeaderDeclaration(functionName)
        return declaration.split(":")[0].replace(".h", "") if declaration else "internal"

    def findEnclosingFunction(self, filePath: str, lineNumber: int) -> Optional[FunctionInfo]:
        self.ensureIndexed()
        for functionInfo in self.functionsByFile.get(filePath, []):
            if functionInfo.startLine <= lineNumber <= functionInfo.endLine:
                return functionInfo
        return None

    def findCallerFunctions(self, functionName: str, maxResults: int = 8) -> List[FunctionInfo]:
        """Functions whose bodies contain a call to functionName."""
        self.ensureIndexed()
        callPattern = re.compile(r"\b" + re.escape(functionName) + r"\s*\(")
        callers: List[FunctionInfo] = []
        seenNames: Set[str] = set()
        for filePath, functionList in self.functionsByFile.items():
            for functionInfo in functionList:
                if functionInfo.name == functionName or functionInfo.name in seenNames:
                    continue
                if callPattern.search(functionInfo.sourceText):
                    callers.append(functionInfo)
                    seenNames.add(functionInfo.name)
                    if len(callers) >= maxResults:
                        return callers
        return callers

    def findPublicApiEntryPoints(self, functionName: str, maxDepth: int = 3, maxResults: int = 8) -> List[str]:
        """Walks up the call graph from an internal function to public API functions that can reach it."""
        self.ensureIndexed()
        publicNames = set(self.publicApi.keys())
        if functionName in publicNames:
            return [functionName]
        frontier = [functionName]
        visited = {functionName}
        entryPoints: List[str] = []
        for _ in range(maxDepth):
            nextFrontier: List[str] = []
            for currentName in frontier:
                for caller in self.findCallerFunctions(currentName, 12):
                    if caller.name in visited:
                        continue
                    visited.add(caller.name)
                    if caller.name in publicNames:
                        entryPoints.append(caller.name)
                    else:
                        nextFrontier.append(caller.name)
            if len(entryPoints) >= maxResults or not nextFrontier:
                break
            frontier = nextFrontier
        return entryPoints[:maxResults]
