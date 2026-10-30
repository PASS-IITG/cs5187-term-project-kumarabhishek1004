"""SQLite store shared by all engines: hypotheses (what to test) and findings (what was confirmed)."""
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import List, Optional

from src.core.appLogger import getLogger, logEvent

logger = getLogger("store")

statusPending = "pending"
statusAuditing = "auditing"
statusVotedDown = "votedDown"
statusConfirmed = "confirmed"
statusHandedToHarness = "handedToHarness"
statusDone = "done"
statusFailed = "failed"


@dataclass
class Hypothesis:
    id: int
    source: str
    title: str
    filePath: str
    functionName: str
    bugClass: str
    description: str
    priority: float
    status: str
    resultNote: str
    parentId: int


class HypothesisStore:
    def __init__(self, databasePath):
        self.connection = sqlite3.connect(str(databasePath), check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        self._createTables()
        logger.info("Hypothesis store opened at %s", databasePath)

    def _createTables(self) -> None:
        with self.lock:
            self.connection.executescript("""
                CREATE TABLE IF NOT EXISTS hypotheses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT, title TEXT, filePath TEXT,
                    functionName TEXT, bugClass TEXT, description TEXT, priority REAL, status TEXT,
                    resultNote TEXT, parentId INTEGER, createdAt REAL, updatedAt REAL,
                    UNIQUE(source, title, functionName));
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, signature TEXT UNIQUE, origin TEXT,
                    reportPath TEXT, votesSummary TEXT, createdAt REAL);
                CREATE TABLE IF NOT EXISTS keyValues (key TEXT PRIMARY KEY, value TEXT);
            """)
            self.connection.commit()

    def addHypothesis(self, source: str, title: str, functionName: str, description: str, filePath: str = "",
                      bugClass: str = "unknown", priority: float = 0.5, parentId: int = 0) -> Optional[int]:
        """Inserts a hypothesis; returns its id, or None if an identical one already exists."""
        now = time.time()
        with self.lock:
            try:
                cursor = self.connection.execute(
                    "INSERT INTO hypotheses (source,title,filePath,functionName,bugClass,description,priority,status,"
                    "resultNote,parentId,createdAt,updatedAt) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (source, title, filePath, functionName, bugClass, description, priority, statusPending, "",
                     parentId, now, now))
                self.connection.commit()
            except sqlite3.IntegrityError:
                logger.debug("Duplicate hypothesis skipped: %s / %s", source, title)
                return None
        logEvent("hypothesisCreated", hypothesisId=cursor.lastrowid, source=source, functionName=functionName,
                 priority=priority)
        logger.info("New hypothesis #%s [%s] %s (priority %.2f)", cursor.lastrowid, source, title, priority)
        return cursor.lastrowid

    def _rowToHypothesis(self, row) -> Hypothesis:
        return Hypothesis(row["id"], row["source"], row["title"], row["filePath"], row["functionName"],
                          row["bugClass"], row["description"], row["priority"], row["status"],
                          row["resultNote"], row["parentId"])

    def getNextPending(self, limit: int, machineIndex: int = 0, machineCount: int = 1) -> List[Hypothesis]:
        """Highest priority pending hypotheses; sharded across machines by id modulo."""
        with self.lock:
            rows = self.connection.execute(
                "SELECT * FROM hypotheses WHERE status=? AND (id % ?) = ? ORDER BY priority DESC, id ASC LIMIT ?",
                (statusPending, machineCount, machineIndex, limit)).fetchall()
        return [self._rowToHypothesis(row) for row in rows]

    def updateStatus(self, hypothesisId: int, status: str, resultNote: str = "") -> None:
        with self.lock:
            self.connection.execute("UPDATE hypotheses SET status=?, resultNote=?, updatedAt=? WHERE id=?",
                                    (status, resultNote[:2000], time.time(), hypothesisId))
            self.connection.commit()
        logger.info("Hypothesis #%s -> %s %s", hypothesisId, status, ("(" + resultNote[:120] + ")") if resultNote else "")

    def resetRetryableHypotheses(self) -> int:
        """Re-queues hypotheses that failed or were voted down only because no LLM could answer (0 votes)."""
        with self.lock:
            cursor = self.connection.execute(
                "UPDATE hypotheses SET status=?, updatedAt=? WHERE (status=? AND resultNote NOT LIKE 'function not found%') "
                "OR (status=? AND resultNote LIKE '0/0%')", (statusPending, time.time(), statusFailed, statusVotedDown))
            self.connection.commit()
        logger.info("Re-queued %d hypotheses that had failed because of LLM problems", cursor.rowcount)
        return cursor.rowcount

    def countByStatus(self) -> dict:
        with self.lock:
            rows = self.connection.execute("SELECT status, COUNT(*) AS total FROM hypotheses GROUP BY status").fetchall()
        return {row["status"]: row["total"] for row in rows}

    def countBySource(self) -> dict:
        with self.lock:
            rows = self.connection.execute("SELECT source, COUNT(*) AS total FROM hypotheses GROUP BY source").fetchall()
        return {row["source"]: row["total"] for row in rows}

    def addFinding(self, kind: str, signature: str, origin: str, reportPath: str, votesSummary: str) -> bool:
        """Returns False when a finding with this signature was already recorded (duplicate)."""
        with self.lock:
            try:
                self.connection.execute(
                    "INSERT INTO findings (kind,signature,origin,reportPath,votesSummary,createdAt) VALUES (?,?,?,?,?,?)",
                    (kind, signature, origin, reportPath, votesSummary, time.time()))
                self.connection.commit()
            except sqlite3.IntegrityError:
                logger.info("Duplicate finding signature ignored: %s", signature)
                return False
        logEvent("findingRecorded", kind=kind, signature=signature, origin=origin, reportPath=reportPath)
        return True

    def listFindings(self) -> list:
        with self.lock:
            return [dict(row) for row in self.connection.execute("SELECT * FROM findings ORDER BY id").fetchall()]

    def getValue(self, key: str, defaultValue: str = "") -> str:
        with self.lock:
            row = self.connection.execute("SELECT value FROM keyValues WHERE key=?", (key,)).fetchone()
        return row["value"] if row else defaultValue

    def setValue(self, key: str, value: str) -> None:
        with self.lock:
            self.connection.execute("INSERT OR REPLACE INTO keyValues (key,value) VALUES (?,?)", (key, value))
            self.connection.commit()
