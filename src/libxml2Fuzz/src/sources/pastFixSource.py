"""Hypothesis source 2: learn bug patterns from past fixes, then search for unfixed siblings and incomplete fixes."""
from typing import Dict, List

from src.core.appConfig import AppConfig
from src.core.appLogger import getLogger, logEvent
from src.core.hypothesisStore import HypothesisStore
from src.core.llmClient import AllProvidersExhaustedError, LlmError, LlmRouter
from src.core.shellRunner import runCommand
from src.core.textUtils import truncateText
from src.prompts import promptLibrary

logger = getLogger("pastFix")


class PastFixSource:
    def __init__(self, config: AppConfig, router: LlmRouter, store: HypothesisStore):
        self.config = config
        self.router = router
        self.store = store
        self.sourceDir = config.getPath("paths.libxml2Dir")
        self.gitTool = config.get("toolchain.git", "git")

    def listFixCommits(self) -> List[Dict[str, str]]:
        grepPattern = self.config.get("discovery.pastFixGrepPattern")
        limit = self.config.get("discovery.pastFixCommitLimit", 25)
        result = runCommand([self.gitTool, "log", "-i", "-E", f"--grep={grepPattern}", f"--max-count={limit}",
                             "--no-merges", "--pretty=%H|%s"], workingDir=self.sourceDir, timeoutSeconds=120)
        commits = []
        for line in result.stdout.splitlines():
            if "|" in line:
                commitHash, subject = line.split("|", 1)
                commits.append({"hash": commitHash, "subject": subject})
        logger.info("Found %d past-fix commits to learn from", len(commits))
        return commits

    def readCommitDiff(self, commitHash: str) -> str:
        diffResult = runCommand([self.gitTool, "show", "--unified=3", "--no-color", commitHash, "--", "*.c", "*.h"],
                                workingDir=self.sourceDir, timeoutSeconds=60, logFailures=False)
        return truncateText(diffResult.stdout, self.config.get("discovery.pastFixMaxDiffChars", 9000))

    def searchSiblingSites(self, regex: str) -> str:
        grepResult = runCommand([self.gitTool, "grep", "-n", "-E", regex, "--", "*.c"], workingDir=self.sourceDir,
                                timeoutSeconds=60, logFailures=False)
        lines = grepResult.stdout.splitlines()[: self.config.get("discovery.pastFixMaxGrepMatches", 60)]
        return "\n".join(lines)

    def mineAllCommits(self) -> int:
        createdCount = 0
        for commit in self.listFixCommits():
            try:
                createdCount += self._processCommit(commit)
            except AllProvidersExhaustedError:
                raise
            except LlmError as llmError:
                logger.error("Skipping commit %s because the LLM failed: %s", commit["hash"][:10], llmError)
        logger.info("Past-fix mining created %d hypotheses", createdCount)
        return createdCount

    def _processCommit(self, commit: Dict[str, str]) -> int:
        diffText = self.readCommitDiff(commit["hash"])
        if not diffText.strip():
            return 0
        pattern = self.router.askJson("analyst", promptLibrary.systemSecurityResearcher,
                                      promptLibrary.buildPastFixAbstractionPrompt(commit["subject"], diffText))
        logEvent("patternAbstracted", commit=commit["hash"][:10], patternName=pattern.get("patternName", ""))
        createdCount = 0
        for idea in pattern.get("incompleteFixIdeas", []) or []:
            if not idea.get("functionName"):
                continue
            hypothesisId = self.store.addHypothesis(
                "incompleteFix", f"Incomplete fix? {commit['subject'][:60]} / {idea['functionName']}", idea["functionName"],
                f"Past fix {commit['hash'][:10]}: {commit['subject']}. Concern: {idea.get('reasoning', '')}",
                bugClass=pattern.get("bugClass", "unknown"), priority=0.75)
            createdCount += 1 if hypothesisId else 0
        regex = (pattern.get("searchRegex") or "").strip()
        if not regex:
            return createdCount
        grepMatches = self.searchSiblingSites(regex)
        if not grepMatches:
            return createdCount
        siblings = self.router.askJson("analyst", promptLibrary.systemSecurityResearcher,
                                       promptLibrary.buildSiblingSearchPrompt(pattern, grepMatches))
        for sibling in siblings if isinstance(siblings, list) else []:
            if not sibling.get("functionName"):
                continue
            hypothesisId = self.store.addHypothesis(
                "pastFixVariant", f"{pattern.get('patternName', 'pattern')} in {sibling['functionName']}",
                sibling["functionName"],
                f"Pattern '{pattern.get('patternName')}': {pattern.get('rootCause', '')}. Why here: {sibling.get('reasoning', '')}",
                filePath=sibling.get("filePath", ""), bugClass=pattern.get("bugClass", "unknown"),
                priority=0.5 + 0.4 * float(sibling.get("confidence", 0.5)))
            createdCount += 1 if hypothesisId else 0
        return createdCount
