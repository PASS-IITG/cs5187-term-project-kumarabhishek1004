"""Multi-LLM majority voting (the master/slave/verifier idea) used to filter suspicions and adjudicate crashes."""
from dataclasses import dataclass, field
from typing import List

from src.core.appConfig import AppConfig
from src.core.appLogger import getLogger, logEvent
from src.core.llmClient import AllProvidersExhaustedError, LlmError, LlmRouter
from src.core.textUtils import truncateText
from src.prompts import promptLibrary

logger = getLogger("voting")


@dataclass
class VoteResult:
    approved: bool
    yesCount: int
    totalVotes: int
    reasons: List[str] = field(default_factory=list)

    def summarize(self) -> str:
        return f"{self.yesCount}/{self.totalVotes} yes; " + " | ".join(reason[:160] for reason in self.reasons)


class VotingPanel:
    def __init__(self, config: AppConfig, router: LlmRouter):
        self.router = router
        self.minVoters = config.get("voting.minVoters", 3)
        self.minApprovalRatio = config.get("voting.minApprovalRatio", 0.5)

    def decide(self, voteLabel: str, question: str, evidence: str,
               systemPrompt: str = promptLibrary.systemJudge) -> VoteResult:
        """Each configured provider votes; if fewer than minVoters exist, providers vote again at higher temperature."""
        providerNames = self.router.getUsableProviderNames()
        if not providerNames:
            logger.error("Cannot vote '%s': no usable LLM provider", voteLabel)
            return VoteResult(False, 0, 0, ["no provider available"])
        voterPlan = [providerNames[index % len(providerNames)] for index in range(max(self.minVoters, len(providerNames)))]
        prompt = promptLibrary.buildVoteInstruction(question, truncateText(evidence, 14000))
        yesCount, totalVotes, reasons = 0, 0, []
        for voterIndex, providerName in enumerate(voterPlan):
            temperature = 0.1 if voterIndex < len(providerNames) else 0.7
            try:
                reply = self.router.askJson("judge", systemPrompt, prompt, temperature, 800, providerName)
            except LlmError as llmError:
                logger.warning("Voter %s failed on '%s': %s", providerName, voteLabel, llmError)
                continue
            if not isinstance(reply, dict):
                continue
            totalVotes += 1
            isYes = str(reply.get("vote", "no")).strip().lower() == "yes"
            yesCount += 1 if isYes else 0
            reasons.append(f"{providerName}:{'yes' if isYes else 'no'}: {reply.get('reason', '')}")
        if totalVotes < min(2, len(voterPlan)):
            logger.error("Vote '%s' could not be completed (%d of %d voters answered): LLM providers are exhausted or failing",
                         voteLabel, totalVotes, len(voterPlan))
            raise AllProvidersExhaustedError(f"vote '{voteLabel}': only {totalVotes} voter(s) answered")
        approved = totalVotes > 0 and (yesCount / totalVotes) > self.minApprovalRatio
        logger.info("VOTE '%s': %d/%d yes -> %s", voteLabel, yesCount, totalVotes, "APPROVED" if approved else "REJECTED")
        logEvent("voteResult", label=voteLabel, yes=yesCount, total=totalVotes, approved=approved)
        return VoteResult(approved, yesCount, totalVotes, reasons)
