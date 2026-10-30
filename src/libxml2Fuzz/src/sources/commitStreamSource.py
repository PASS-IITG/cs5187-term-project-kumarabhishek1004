"""Hypothesis source 3: audit every recent upstream commit; new code has had the least fuzzing."""
from typing import Dict, List

from src.core.appConfig import AppConfig
from src.core.appLogger import getLogger
from src.core.hypothesisStore import HypothesisStore
from src.core.llmClient import AllProvidersExhaustedError, LlmError, LlmRouter
from src.core.shellRunner import runCommand
from src.core.textUtils import truncateText
from src.prompts import promptLibrary

logger = getLogger("commitStream")


class CommitStreamSource:
    def __init__(self, config: AppConfig, router: LlmRouter, store: HypothesisStore):
        self.config = config
        self.router = router
        self.store = store
        self.sourceDir = config.getPath("paths.libxml2Dir")
        self.gitTool = config.get("toolchain.git", "git")

    def listRecentCommits(self) -> List[Dict[str, str]]:
        days = self.config.get("discovery.commitStreamDays", 120)
        limit = self.config.get("discovery.commitStreamMaxCommits", 40)
        result = runCommand([self.gitTool, "log", f"--since={days}.days", f"--max-count={limit}", "--no-merges",
                             "--pretty=%H|%s"], workingDir=self.sourceDir, timeoutSeconds=60)
        commits = [{"hash": line.split("|", 1)[0], "subject": line.split("|", 1)[1]}
                   for line in result.stdout.splitlines() if "|" in line]
        alreadyReviewed = set(self.store.getValue("reviewedCommits").split(","))
        freshCommits = [commit for commit in commits if commit["hash"] not in alreadyReviewed]
        logger.info("Commit stream: %d recent commits, %d not yet reviewed", len(commits), len(freshCommits))
        return freshCommits

    def reviewNewCommits(self) -> int:
        reviewedHashes = set(self.store.getValue("reviewedCommits").split(","))
        createdCount = 0
        for commit in self.listRecentCommits():
            diffResult = runCommand([self.gitTool, "show", "--unified=3", "--no-color", commit["hash"], "--", "*.c", "*.h"],
                                    workingDir=self.sourceDir, timeoutSeconds=60, logFailures=False)
            diffText = truncateText(diffResult.stdout, self.config.get("discovery.pastFixMaxDiffChars", 9000))
            if not diffText.strip():
                reviewedHashes.add(commit["hash"])
                continue
            try:
                findings = self.router.askJson("auditor", promptLibrary.systemSecurityResearcher,
                                               promptLibrary.buildCommitReviewPrompt(commit["subject"], diffText))
            except AllProvidersExhaustedError:
                raise
            except LlmError as llmError:
                logger.error("Commit %s not reviewed (LLM failure): %s", commit["hash"][:10], llmError)
                continue
            for finding in findings if isinstance(findings, list) else []:
                if not finding.get("functionName"):
                    continue
                hypothesisId = self.store.addHypothesis(
                    "commitStream", f"{commit['subject'][:60]} / {finding['functionName']}", finding["functionName"],
                    f"Recent commit {commit['hash'][:10]} ({commit['subject']}): {finding.get('reasoning', '')}",
                    bugClass=finding.get("bugClass", "unknown"), priority=0.55 + 0.4 * float(finding.get("confidence", 0.5)))
                createdCount += 1 if hypothesisId else 0
            reviewedHashes.add(commit["hash"])
            self.store.setValue("reviewedCommits", ",".join(sorted(reviewedHashes)))
        logger.info("Commit stream review created %d hypotheses", createdCount)
        return createdCount
