"""Logging setup: colored console, rolling debug log, error log and a JSON-lines event log for metrics."""
import json
import logging
import sys
import threading
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path

logFormat = "%(asctime)s | %(levelname)-8s | %(name)-16s | %(message)s"
eventLogPath = None
eventLogLock = threading.Lock()


class ColorFormatter(logging.Formatter):
    colorByLevel = {
        logging.DEBUG: "\033[90m",
        logging.INFO: "\033[0m",
        logging.WARNING: "\033[33m",
        logging.ERROR: "\033[31m",
        logging.CRITICAL: "\033[1;41m",
    }
    resetCode = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        formattedText = super().format(record)
        if not sys.stderr.isatty():
            return formattedText
        return self.colorByLevel.get(record.levelno, "") + formattedText + self.resetCode


def setupLogging(logDirectory, consoleLevel: str = "INFO") -> None:
    """Creates fuzz.log (everything), errors.log (warnings+) and events.jsonl (structured metrics)."""
    global eventLogPath
    logDirPath = Path(logDirectory)
    logDirPath.mkdir(parents=True, exist_ok=True)
    eventLogPath = logDirPath / "events.jsonl"

    rootLogger = logging.getLogger()
    rootLogger.setLevel(logging.DEBUG)
    for existingHandler in list(rootLogger.handlers):
        rootLogger.removeHandler(existingHandler)

    consoleHandler = logging.StreamHandler(sys.stderr)
    consoleHandler.setLevel(getattr(logging, consoleLevel.upper(), logging.INFO))
    consoleHandler.setFormatter(ColorFormatter(logFormat))

    debugHandler = RotatingFileHandler(logDirPath / "fuzz.log", maxBytes=20_000_000, backupCount=5, encoding="utf-8")
    debugHandler.setLevel(logging.DEBUG)
    debugHandler.setFormatter(logging.Formatter(logFormat))

    errorHandler = RotatingFileHandler(logDirPath / "errors.log", maxBytes=5_000_000, backupCount=3, encoding="utf-8")
    errorHandler.setLevel(logging.WARNING)
    errorHandler.setFormatter(logging.Formatter(logFormat))

    for handler in (consoleHandler, debugHandler, errorHandler):
        rootLogger.addHandler(handler)

    for noisyLoggerName in ("urllib3", "requests"):
        logging.getLogger(noisyLoggerName).setLevel(logging.WARNING)


def getLogger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def logStageBanner(logger: logging.Logger, title: str) -> None:
    logger.info("=" * 70)
    logger.info("STAGE: %s", title)
    logger.info("=" * 70)


def logEvent(eventType: str, **fields) -> None:
    """Appends one structured record to events.jsonl. These records become the tables of the paper."""
    if eventLogPath is None:
        return
    record = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"), "eventType": eventType}
    record.update(fields)
    with eventLogLock:
        with open(eventLogPath, "a", encoding="utf-8") as eventFile:
            eventFile.write(json.dumps(record, default=str) + "\n")
