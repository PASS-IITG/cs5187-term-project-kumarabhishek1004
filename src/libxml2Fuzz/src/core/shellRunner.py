"""Runs external commands with timeouts and consistent logging."""
import os
import subprocess
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

from src.core.appLogger import getLogger
from src.core.textUtils import tailLines

logger = getLogger("shell")


@dataclass
class CommandResult:
    command: List[str]
    returnCode: int
    stdout: str
    stderr: str
    durationSeconds: float
    timedOut: bool

    @property
    def succeeded(self) -> bool:
        return self.returnCode == 0 and not self.timedOut

    @property
    def combinedOutput(self) -> str:
        return self.stdout + "\n" + self.stderr


def decodeOutput(rawValue) -> str:
    if rawValue is None:
        return ""
    if isinstance(rawValue, bytes):
        return rawValue.decode("utf-8", errors="replace")
    return rawValue


def runCommand(commandArgs: List[str], workingDir=None, timeoutSeconds: int = 600,
               envOverrides: Optional[Dict[str, str]] = None, logFailures: bool = True) -> CommandResult:
    """Runs a command, never raises; returns exit code 127 if the tool is missing, timedOut=True on timeout."""
    environment = os.environ.copy()
    if envOverrides:
        environment.update(envOverrides)
    printableCommand = " ".join(str(part) for part in commandArgs)
    logger.debug("RUN: %s (cwd=%s, timeout=%ss)", printableCommand[:400], workingDir, timeoutSeconds)
    startTime = time.time()
    try:
        completed = subprocess.run([str(part) for part in commandArgs], cwd=workingDir, env=environment,
                                   capture_output=True, timeout=timeoutSeconds)
        result = CommandResult(list(commandArgs), completed.returncode, decodeOutput(completed.stdout),
                               decodeOutput(completed.stderr), time.time() - startTime, False)
    except subprocess.TimeoutExpired as timeoutError:
        result = CommandResult(list(commandArgs), -9, decodeOutput(timeoutError.stdout),
                               decodeOutput(timeoutError.stderr), time.time() - startTime, True)
        if logFailures:
            logger.warning("TIMEOUT after %ss: %s", timeoutSeconds, printableCommand[:200])
        return result
    except FileNotFoundError:
        logger.error("TOOL NOT FOUND: '%s' is not installed or not on PATH", commandArgs[0])
        return CommandResult(list(commandArgs), 127, "", f"tool not found: {commandArgs[0]}", 0.0, False)

    if not result.succeeded and logFailures:
        logger.warning("COMMAND FAILED (exit %s, %.1fs): %s\n%s", result.returnCode, result.durationSeconds,
                       printableCommand[:200], tailLines(result.stderr or result.stdout, 12))
    return result
