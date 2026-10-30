"""Small helpers for parsing LLM output and trimming text."""
import hashlib
import json
import re
from typing import Any, List, Optional

codeFencePattern = re.compile(r"```([A-Za-z0-9_+\-]*)[ \t]*\n(.*?)```", re.DOTALL)


def stripCodeFences(text: str) -> str:
    stripped = text.strip()
    fenceMatch = codeFencePattern.search(stripped)
    if fenceMatch and fenceMatch.group(1).lower() in ("json", ""):
        return fenceMatch.group(2).strip()
    return stripped


def findBalancedJsonEnd(text: str, startIndex: int) -> int:
    """Returns the index after the JSON object/array that starts at startIndex, or -1."""
    openChar = text[startIndex]
    closeChar = "}" if openChar == "{" else "]"
    depth = 0
    inString = False
    isEscaped = False
    for index in range(startIndex, len(text)):
        currentChar = text[index]
        if inString:
            if isEscaped:
                isEscaped = False
            elif currentChar == "\\":
                isEscaped = True
            elif currentChar == '"':
                inString = False
            continue
        if currentChar == '"':
            inString = True
        elif currentChar == openChar:
            depth += 1
        elif currentChar == closeChar:
            depth -= 1
            if depth == 0:
                return index + 1
    return -1


def extractJsonFromText(text: str) -> Any:
    """Parses JSON from an LLM reply, tolerating code fences and surrounding prose. Raises ValueError."""
    cleaned = stripCodeFences(text)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    for startChar in ("{", "["):
        searchFrom = 0
        while True:
            startIndex = cleaned.find(startChar, searchFrom)
            if startIndex == -1:
                break
            endIndex = findBalancedJsonEnd(cleaned, startIndex)
            if endIndex != -1:
                try:
                    return json.loads(cleaned[startIndex:endIndex])
                except json.JSONDecodeError:
                    pass
            searchFrom = startIndex + 1
    raise ValueError("No valid JSON found in LLM reply")


def extractCodeBlock(text: str, preferredLanguages: Optional[List[str]] = None) -> Optional[str]:
    """Returns the best fenced code block; prefers the given languages, then the longest block."""
    blocks = [(match.group(1).lower(), match.group(2)) for match in codeFencePattern.finditer(text)]
    if not blocks:
        return None
    if preferredLanguages:
        preferredBlocks = [code for language, code in blocks if language in preferredLanguages]
        if preferredBlocks:
            return max(preferredBlocks, key=len).strip() + "\n"
    return max((code for _, code in blocks), key=len).strip() + "\n"


def truncateText(text: str, maxChars: int, marker: str = "\n...[truncated]...\n") -> str:
    if len(text) <= maxChars:
        return text
    headSize = int(maxChars * 0.7)
    tailSize = maxChars - headSize
    return text[:headSize] + marker + text[-tailSize:]


def tailLines(text: str, lineCount: int) -> str:
    return "\n".join(text.strip().splitlines()[-lineCount:])


def computeShortHash(text: str, length: int = 10) -> str:
    return hashlib.sha1(text.encode("utf-8", errors="replace")).hexdigest()[:length]


def makeSafeName(text: str, maxLength: int = 60) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", text).strip("_")[:maxLength] or "unnamed"
