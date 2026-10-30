"""Checks out libxml2 and builds it in several sanitizer/coverage variants; compiles harnesses against them."""
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from src.core.appConfig import AppConfig, templatesDir
from src.core.appLogger import getLogger, logEvent
from src.core.shellRunner import CommandResult, runCommand
from src.core.textUtils import tailLines

logger = getLogger("builder")

commonCompileFlags = ["-g", "-O1", "-fno-omit-frame-pointer"]


@dataclass
class VariantSpec:
    name: str
    libraryFlags: List[str]      # flags used when compiling libxml2 itself
    fuzzerFlags: List[str]       # flags for linking a libFuzzer harness
    standaloneFlags: List[str]   # flags for compiling PoCs / oracle programs
    extraCmakeOptions: List[str] = field(default_factory=list)


variantSpecs: Dict[str, VariantSpec] = {
    "asanUbsan": VariantSpec(
        "asanUbsan",
        ["-fsanitize=address,undefined,fuzzer-no-link", "-fno-sanitize-recover=undefined"],
        ["-fsanitize=fuzzer,address,undefined", "-fno-sanitize-recover=undefined"],
        ["-fsanitize=address,undefined", "-fno-sanitize-recover=undefined"]),
    "coverage": VariantSpec(
        "coverage",
        ["-fprofile-instr-generate", "-fcoverage-mapping"],
        ["-fsanitize=fuzzer", "-fprofile-instr-generate", "-fcoverage-mapping"],
        ["-fprofile-instr-generate", "-fcoverage-mapping"]),
    "msan": VariantSpec(
        "msan",
        ["-fsanitize=memory", "-fsanitize-memory-track-origins=2", "-fsanitize=fuzzer-no-link"],
        ["-fsanitize=fuzzer,memory", "-fsanitize-memory-track-origins=2"],
        ["-fsanitize=memory", "-fsanitize-memory-track-origins=2"]),
    "asan32": VariantSpec(
        "asan32",
        ["-m32", "-fsanitize=address,undefined,fuzzer-no-link"],
        ["-m32", "-fsanitize=fuzzer,address,undefined"],
        ["-m32", "-fsanitize=address,undefined"]),
}


@dataclass
class BuildInfo:
    variantName: str
    libraryPath: Path
    includeFlags: List[str]


class LibxmlBuilder:
    def __init__(self, config: AppConfig):
        self.config = config
        self.sourceDir = config.getPath("paths.libxml2Dir")
        self.workDir = config.getPath("paths.workDir")
        self.cCompiler = config.get("toolchain.cCompiler", "clang")
        self.cxxCompiler = config.get("toolchain.cxxCompiler", "clang++")
        self.builtVariants: Dict[str, BuildInfo] = {}

    # ------------------------------------------------------------------ toolchain and source
    def checkToolchain(self) -> bool:
        """Verifies that required tools are installed and logs their versions."""
        allToolsPresent = True
        for toolKey in ("git", "cmake", "cCompiler", "cxxCompiler", "llvmProfdata", "llvmCov"):
            toolName = self.config.get(f"toolchain.{toolKey}")
            result = runCommand([toolName, "--version"], timeoutSeconds=20, logFailures=False)
            if result.returnCode == 127:
                logger.error("MISSING TOOL: %s (%s). Install it or change toolchain.%s in settings.json",
                             toolName, toolKey, toolKey)
                allToolsPresent = False
            else:
                logger.info("Tool OK: %s -> %s", toolName, (result.stdout or result.stderr).splitlines()[0] if (result.stdout or result.stderr) else "")
        return allToolsPresent

    def ensureSourceCheckedOut(self, updateToLatest: bool = False) -> bool:
        gitTool = self.config.get("toolchain.git", "git")
        if not (self.sourceDir / ".git").exists():
            logger.info("Cloning libxml2 into %s ...", self.sourceDir)
            self.sourceDir.parent.mkdir(parents=True, exist_ok=True)
            result = runCommand([gitTool, "clone", self.config.get("paths.libxml2RepoUrl"), str(self.sourceDir)],
                                timeoutSeconds=1800)
            return result.succeeded
        if updateToLatest:
            logger.info("Updating libxml2 to latest upstream master ...")
            return runCommand([gitTool, "pull", "--ff-only"], workingDir=self.sourceDir, timeoutSeconds=600).succeeded
        return True

    def getCurrentCommit(self) -> str:
        result = runCommand([self.config.get("toolchain.git", "git"), "rev-parse", "HEAD"], workingDir=self.sourceDir,
                            timeoutSeconds=30, logFailures=False)
        return result.stdout.strip()

    # ------------------------------------------------------------------ library builds
    def buildVariant(self, variantName: str, forceRebuild: bool = False) -> Optional[BuildInfo]:
        """Builds libxml2 as a static library for one variant using cmake. Returns None on failure."""
        if variantName in self.builtVariants and not forceRebuild:
            return self.builtVariants[variantName]
        spec = variantSpecs[variantName]
        buildDir = self.workDir / "builds" / variantName
        if forceRebuild and buildDir.exists():
            shutil.rmtree(buildDir)
        flagsText = " ".join(commonCompileFlags + spec.libraryFlags)
        configureCommand = [
            self.config.get("toolchain.cmake", "cmake"), "-S", str(self.sourceDir), "-B", str(buildDir),
            f"-DCMAKE_C_COMPILER={self.cCompiler}", f"-DCMAKE_C_FLAGS={flagsText}",
            "-DBUILD_SHARED_LIBS=OFF", "-DCMAKE_BUILD_TYPE=Debug"] + self.config.get("libxml2.cmakeExtraOptions", [])
        logger.info("Configuring libxml2 variant '%s' ...", variantName)
        if not runCommand(configureCommand, timeoutSeconds=600).succeeded:
            logger.error("CMAKE CONFIGURE FAILED for variant %s", variantName)
            return None
        logger.info("Compiling libxml2 variant '%s' (this can take a few minutes) ...", variantName)
        buildResult = runCommand([self.config.get("toolchain.cmake", "cmake"), "--build", str(buildDir), "-j",
                                  str(self.config.get("toolchain.buildJobs", 8))], timeoutSeconds=3600)
        if not buildResult.succeeded:
            logger.error("BUILD FAILED for variant %s:\n%s", variantName, tailLines(buildResult.combinedOutput, 20))
            return None
        libraryPath = self._findStaticLibrary(buildDir)
        if libraryPath is None:
            logger.error("Static library libxml2.a not found in %s", buildDir)
            return None
        buildInfo = BuildInfo(variantName, libraryPath, ["-I" + str(self.sourceDir / "include"), "-I" + str(buildDir)])
        self.builtVariants[variantName] = buildInfo
        logEvent("variantBuilt", variant=variantName, library=str(libraryPath), commit=self.getCurrentCommit())
        logger.info("Variant '%s' ready: %s", variantName, libraryPath)
        return buildInfo

    def _findStaticLibrary(self, buildDir: Path) -> Optional[Path]:
        candidates = sorted(buildDir.glob("libxml2*.a"))
        return candidates[0] if candidates else None

    def buildAllEnabledVariants(self) -> bool:
        allBuilt = True
        for variantName in self.config.get("libxml2.enabledVariants", ["asanUbsan"]):
            if self.buildVariant(variantName) is None:
                allBuilt = False
        return allBuilt

    def getBuildInfo(self, variantName: str) -> Optional[BuildInfo]:
        return self.builtVariants.get(variantName) or self.buildVariant(variantName)

    def getIncludeFlags(self, variantName: str = "asanUbsan") -> List[str]:
        buildInfo = self.getBuildInfo(variantName)
        return buildInfo.includeFlags if buildInfo else ["-I" + str(self.sourceDir / "include")]

    # ------------------------------------------------------------------ compiling programs against a variant
    def _compile(self, variantName: str, sourcePaths: List[Path], outputPath: Path, useFuzzer: bool,
                 extraSources: Optional[List[Path]] = None, timeoutSeconds: int = 300) -> CommandResult:
        buildInfo = self.getBuildInfo(variantName)
        if buildInfo is None:
            return CommandResult(["compile"], 1, "", f"variant {variantName} is not built", 0.0, False)
        spec = variantSpecs[variantName]
        isCpp = any(str(path).endswith((".cc", ".cpp", ".cxx")) for path in sourcePaths)
        compiler = self.cxxCompiler if isCpp else self.cCompiler
        languageFlags = ["-std=c++17"] if isCpp else []
        outputPath.parent.mkdir(parents=True, exist_ok=True)
        command = ([compiler] + commonCompileFlags + languageFlags + (spec.fuzzerFlags if useFuzzer else spec.standaloneFlags)
                   + buildInfo.includeFlags + ["-I" + str(templatesDir)] + [str(path) for path in sourcePaths]
                   + [str(path) for path in (extraSources or [])] + [str(buildInfo.libraryPath), "-lm", "-lpthread",
                                                                   "-o", str(outputPath)])
        return runCommand(command, timeoutSeconds=timeoutSeconds, logFailures=False)

    def compileFuzzHarness(self, variantName: str, harnessPath: Path, outputPath: Path,
                           extraSources: Optional[List[Path]] = None) -> CommandResult:
        result = self._compile(variantName, [harnessPath], outputPath, True, extraSources)
        logger.info("Compile harness %s [%s]: %s", harnessPath.name, variantName, "OK" if result.succeeded else "FAILED")
        return result

    def compileStandaloneProgram(self, variantName: str, sourcePath: Path, outputPath: Path) -> CommandResult:
        result = self._compile(variantName, [sourcePath], outputPath, False)
        logger.info("Compile program %s [%s]: %s", sourcePath.name, variantName, "OK" if result.succeeded else "FAILED")
        return result
