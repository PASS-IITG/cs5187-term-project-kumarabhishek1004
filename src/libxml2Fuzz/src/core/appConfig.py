"""Loads settings.json, applies environment-variable overrides and exposes dotted-key access."""
import glob
import json
import os
import re
import shutil
from pathlib import Path
from typing import Any, List, Optional

placeholderPrefix = "PASTE_"
projectRoot = Path(__file__).resolve().parents[2]
templatesDir = projectRoot / "src" / "templates"


def isPlaceholder(value: Any) -> bool:
    """Returns True when a setting is empty or still contains the PASTE_... placeholder."""
    return not isinstance(value, str) or value.strip() == "" or value.strip().startswith(placeholderPrefix)


def findVersionedTool(toolName: str) -> Optional[str]:
    """Finds e.g. llvm-cov when it is only installed as llvm-cov-18 or under /usr/lib/llvm-18/bin (or Homebrew)."""
    searchDirs: List[str] = sorted(glob.glob("/usr/lib/llvm-*/bin"), reverse=True) + [
        "/opt/homebrew/opt/llvm/bin", "/usr/local/opt/llvm/bin"]
    for searchDir in searchDirs:
        candidate = Path(searchDir) / toolName
        if candidate.exists():
            return str(candidate)
    for version in range(25, 9, -1):
        versionedPath = shutil.which(f"{toolName}-{version}")
        if versionedPath:
            return versionedPath
    return None


class AppConfig:
    def __init__(self, configPath: str):
        self.configPath = Path(configPath)
        self.data = self._loadJsonFile()
        self.startupNotes: List[str] = []
        self._applyEnvironmentOverrides()
        self._resolvePaths()
        self._autoDetectToolchain()

    def _loadJsonFile(self) -> dict:
        if not self.configPath.exists():
            raise FileNotFoundError(f"Config file not found: {self.configPath}")
        with open(self.configPath, "r", encoding="utf-8") as configFile:
            return json.load(configFile)

    def _applyEnvironmentOverrides(self) -> None:
        """Lets keys/models come from env vars, e.g. ANTHROPIC_API_KEY or OPENAI_MODEL."""
        for providerName, providerData in self.data["llm"]["providers"].items():
            keyEnvName = providerData.get("apiKeyEnv")
            if keyEnvName and os.environ.get(keyEnvName):
                providerData["apiKey"] = os.environ[keyEnvName]
            envKey = os.environ.get(f"{providerName.upper()}_API_KEY")
            envModel = os.environ.get(f"{providerName.upper()}_MODEL")
            if envKey:
                providerData["apiKey"] = envKey
            if envModel:
                providerData["model"] = envModel

    def _resolvePaths(self) -> None:
        for pathKey, pathValue in self.data["paths"].items():
            if pathKey.endswith("Url"):
                continue
            absolutePath = Path(pathValue)
            if not absolutePath.is_absolute():
                absolutePath = projectRoot / absolutePath
            self.data["paths"][pathKey] = str(absolutePath)

    def _autoDetectToolchain(self) -> None:
        """If a configured LLVM tool is not on PATH, look for a versioned install and use it (notes are logged later)."""
        toolchain = self.data.get("toolchain", {})
        for settingKey in ("llvmProfdata", "llvmCov", "cCompiler", "cxxCompiler"):
            configuredName = toolchain.get(settingKey)
            if not configuredName or shutil.which(configuredName):
                continue
            foundPath = findVersionedTool(Path(configuredName).name)
            if foundPath:
                toolchain[settingKey] = foundPath
                self.startupNotes.append(f"Auto-detected {settingKey}: '{configuredName}' not on PATH, using {foundPath}")

    def findUnsafePathProblems(self) -> List[str]:
        """libFuzzer -fork mode builds child commands as an UNQUOTED shell string, so characters such as ( ) & ; or spaces in any
        path break every job. Returns a description of each offending path (empty list = OK)."""
        problems: List[str] = []
        pathsToCheck = {"project folder": str(projectRoot), "paths.workDir": self.data["paths"]["workDir"],
                        "paths.libxml2Dir": self.data["paths"]["libxml2Dir"]}
        for label, pathText in pathsToCheck.items():
            badCharacters = sorted(set(re.findall(r"[^A-Za-z0-9_\-./]", pathText)))
            if badCharacters:
                problems.append(f"{label} = {pathText}  contains unsafe characters {badCharacters}")
        return problems

    def get(self, dottedKey: str, default: Any = None) -> Any:
        currentValue: Any = self.data
        for keyPart in dottedKey.split("."):
            if not isinstance(currentValue, dict) or keyPart not in currentValue:
                return default
            currentValue = currentValue[keyPart]
        return currentValue

    def getPath(self, dottedKey: str) -> Path:
        return Path(self.get(dottedKey))
