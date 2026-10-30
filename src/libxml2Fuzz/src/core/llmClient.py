"""Multi-provider LLM client with role routing, retries, fallbacks and explicit limit/quota diagnostics."""
import random
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import requests

from src.core.appConfig import AppConfig, isPlaceholder
from src.core.appLogger import getLogger, logEvent
from src.core.textUtils import extractJsonFromText

logger = getLogger("llm")

errorRateLimited = "rateLimited"
errorQuotaExhausted = "quotaExhausted"
errorAuthFailed = "authFailed"
errorTransient = "transient"
errorBadRequest = "badRequest"
errorRequestTooLarge = "requestTooLarge"

quotaMarkers = ["insufficientquota", "exceededyourcurrentquota", "creditbalanceistoolow", "perday", "daily",
                "billingdetails", "outofcredits", "paymentrequired"]


class LlmError(Exception):
    pass


class ProviderExhaustedError(LlmError):
    """Raised when one provider can no longer be used (quota, auth, soft cap, repeated rate limits)."""


class AllProvidersExhaustedError(LlmError):
    """Raised when no configured provider can serve the request."""


@dataclass
class ProviderState:
    name: str
    apiType: str
    apiKey: str
    model: str
    baseUrl: str
    maxCalls: int
    maxTotalTokens: int
    maxTokensField: str
    extraRequestFields: dict = field(default_factory=dict)
    disabledReason: str = ""
    cooldownUntil: float = 0.0
    callCount: int = 0
    failedCallCount: int = 0
    inputTokens: int = 0
    outputTokens: int = 0
    rateLimitHits: int = 0
    lastCallTime: float = 0.0

    def isConfigured(self) -> bool:
        return not isPlaceholder(self.apiKey) and not isPlaceholder(self.model)

    def isUsable(self) -> bool:
        return self.isConfigured() and not self.disabledReason

    def isCoolingDown(self) -> bool:
        return time.time() < self.cooldownUntil


def parseTryAgainSeconds(bodyText: str) -> Optional[float]:
    """Reads hints like 'Please try again in 1.2s' / '2m59.56s' / '500ms' from an error body."""
    match = re.search(r"try again in ([0-9hmsµ\.]+)", bodyText)
    if not match:
        return None
    unitSeconds = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0}
    parts = re.findall(r"(\d+(?:\.\d+)?)(ms|h|m|s)", match.group(1))
    return sum(float(amount) * unitSeconds[unit] for amount, unit in parts) if parts else None


def classifyHttpError(statusCode: int, bodyText: str) -> str:
    """Maps an HTTP failure to: authFailed, quotaExhausted, rateLimited, transient, requestTooLarge, badRequest."""
    compactBody = bodyText.lower().replace(" ", "").replace("_", "")
    hasQuotaMarker = any(marker in compactBody for marker in quotaMarkers)
    if statusCode == 413 or "requesttoolarge" in compactBody:
        return errorRequestTooLarge
    if statusCode in (401, 403):
        return errorQuotaExhausted if hasQuotaMarker else errorAuthFailed
    if statusCode == 402:
        return errorQuotaExhausted
    if statusCode == 429:
        return errorQuotaExhausted if hasQuotaMarker else errorRateLimited
    if statusCode == 400 and hasQuotaMarker:
        return errorQuotaExhausted
    if statusCode in (408, 409, 500, 502, 503, 504, 529):
        return errorTransient
    return errorBadRequest


class LlmRouter:
    def __init__(self, config: AppConfig):
        self.config = config
        self.providers: Dict[str, ProviderState] = {}
        self.roleOrder: Dict[str, List[str]] = config.get("llm.roles", {})
        self.requestTimeout = config.get("llm.requestTimeoutSeconds", 180)
        self.maxRetries = config.get("llm.maxRetries", 5)
        self.baseBackoff = config.get("llm.baseBackoffSeconds", 4)
        self.maxBackoff = config.get("llm.maxBackoffSeconds", 90)
        self.cooldownSeconds = config.get("llm.rateLimitCooldownSeconds", 120)
        self.minCallInterval = config.get("llm.minSecondsBetweenCalls", 0.5)
        self.defaultMaxTokens = config.get("llm.defaultMaxTokens", 4096)
        self.maxTokensCap = config.get("llm.maxTokensCap", 0)
        self.maxQuotaWaitSeconds = config.get("llm.maxQuotaWaitSeconds", 900)
        self._loadProviders()

    def _loadProviders(self) -> None:
        for providerName, providerData in self.config.get("llm.providers", {}).items():
            state = ProviderState(
                name=providerName, apiType=providerData["apiType"], apiKey=providerData.get("apiKey", ""),
                model=providerData.get("model", ""), baseUrl=providerData.get("baseUrl", "").rstrip("/"),
                maxCalls=providerData.get("maxCalls", 0), maxTotalTokens=providerData.get("maxTotalTokens", 0),
                maxTokensField=providerData.get("maxTokensField", "max_tokens"),
                extraRequestFields=providerData.get("extraRequestFields", {}))
            self.providers[providerName] = state
            if state.isConfigured():
                logger.info("LLM provider READY: %s (model=%s)", providerName, state.model)
            else:
                logger.warning("LLM provider SKIPPED: %s (API key or model still a placeholder)", providerName)
        if not self.getUsableProviderNames():
            logger.error("NO LLM PROVIDER CONFIGURED. Put API keys in config/settings.json or environment variables.")

    def getUsableProviderNames(self) -> List[str]:
        return [name for name, state in self.providers.items() if state.isUsable()]

    def _buildCandidateOrder(self, role: str) -> List[str]:
        preferredNames = [name for name in self.roleOrder.get(role, []) if name in self.providers]
        remainingNames = [name for name in self.providers if name not in preferredNames]
        return preferredNames + remainingNames

    # ------------------------------------------------------------------ public API
    def askText(self, role: str, systemPrompt: str, userPrompt: str, temperature: float = 0.2,
                maxTokens: Optional[int] = None, providerName: Optional[str] = None, _alreadyWaited: bool = False) -> str:
        """Sends a prompt using the role's preferred provider, falling back to others on exhaustion."""
        candidateNames = [providerName] if providerName else self._buildCandidateOrder(role)
        lastErrorMessage = "no provider available"
        for name in self._orderByCooldown(candidateNames):
            state = self.providers[name]
            if not state.isUsable():
                continue
            try:
                return self._callProvider(state, role, systemPrompt, userPrompt, temperature,
                                          maxTokens or self.defaultMaxTokens)
            except ProviderExhaustedError as exhaustedError:
                lastErrorMessage = str(exhaustedError)
                logger.warning("Provider %s unavailable for role '%s' -> trying next provider", name, role)
            except LlmError as llmError:
                lastErrorMessage = str(llmError)
                logger.warning("Provider %s failed for role '%s': %s -> trying next provider", name, role, llmError)
        pausedWaits = [state.cooldownUntil - time.time() for state in self.providers.values()
                       if state.isUsable() and state.cooldownUntil > time.time() and (providerName in (None, state.name))]
        if pausedWaits and not _alreadyWaited and min(pausedWaits) <= self.maxQuotaWaitSeconds + 5:
            waitSeconds = min(pausedWaits) + 1
            logger.warning("All usable providers are paused by token limits. Sleeping %.0fs, then retrying this request once.", waitSeconds)
            time.sleep(waitSeconds)
            return self.askText(role, systemPrompt, userPrompt, temperature, maxTokens, providerName, _alreadyWaited=True)
        logger.error("ALL LLM PROVIDERS EXHAUSTED/FAILED for role '%s': %s", role, lastErrorMessage)
        raise AllProvidersExhaustedError(lastErrorMessage)

    def askJson(self, role: str, systemPrompt: str, userPrompt: str, temperature: float = 0.2,
                maxTokens: Optional[int] = None, providerName: Optional[str] = None) -> Any:
        """Like askText but parses JSON; retries once asking the model to fix its formatting."""
        replyText = self.askText(role, systemPrompt, userPrompt, temperature, maxTokens, providerName)
        try:
            return extractJsonFromText(replyText)
        except ValueError:
            logger.warning("LLM reply was not valid JSON (role=%s); asking for a corrected reply", role)
        retryPrompt = userPrompt + "\n\nYour previous reply was not valid JSON. Reply again with ONLY valid JSON."
        replyText = self.askText(role, systemPrompt, retryPrompt, 0.0, maxTokens, providerName)
        try:
            return extractJsonFromText(replyText)
        except ValueError as parseError:
            logger.error("LLM reply still not valid JSON after retry. First 300 chars: %s", replyText[:300])
            raise LlmError("invalid JSON from LLM") from parseError

    def getUsageSummary(self) -> str:
        lines = ["LLM usage summary:"]
        for name, state in self.providers.items():
            status = "DISABLED: " + state.disabledReason if state.disabledReason else (
                "ready" if state.isConfigured() else "not configured")
            lines.append(f"  {name:10s} calls={state.callCount} failed={state.failedCallCount} "
                         f"rateLimitHits={state.rateLimitHits} inTokens={state.inputTokens} "
                         f"outTokens={state.outputTokens} status={status}")
        return "\n".join(lines)

    def logUsageSummary(self) -> None:
        logger.info(self.getUsageSummary())

    # ------------------------------------------------------------------ internals
    def _orderByCooldown(self, candidateNames: List[str]) -> List[str]:
        """Providers that are cooling down after rate limits go last; waits if all are cooling down."""
        usableNames = [name for name in candidateNames if self.providers[name].isUsable()]
        readyNames = [name for name in usableNames if not self.providers[name].isCoolingDown()]
        coolingNames = [name for name in usableNames if self.providers[name].isCoolingDown()]
        if not readyNames and coolingNames:
            waitSeconds = min(self.providers[name].cooldownUntil for name in coolingNames) - time.time()
            if waitSeconds > 0:
                logger.warning("All providers are rate-limited. Waiting %.0fs for the earliest cooldown to end", waitSeconds)
                time.sleep(waitSeconds)
        return readyNames + coolingNames

    def _disableProvider(self, state: ProviderState, reason: str) -> None:
        state.disabledReason = reason
        logger.error("PROVIDER DISABLED: %s -> %s", state.name, reason)
        logEvent("providerDisabled", provider=state.name, reason=reason)

    def _checkSoftLimits(self, state: ProviderState) -> None:
        if state.maxCalls and state.callCount >= state.maxCalls:
            self._disableProvider(state, f"soft call cap reached ({state.maxCalls} calls)")
            raise ProviderExhaustedError(state.disabledReason)
        if state.maxTotalTokens and (state.inputTokens + state.outputTokens) >= state.maxTotalTokens:
            self._disableProvider(state, f"soft token cap reached ({state.maxTotalTokens} tokens)")
            raise ProviderExhaustedError(state.disabledReason)

    def _waitForMinimumInterval(self, state: ProviderState) -> None:
        waitSeconds = self.minCallInterval - (time.time() - state.lastCallTime)
        if waitSeconds > 0:
            time.sleep(waitSeconds)

    def _computeBackoffSeconds(self, attemptNumber: int, retryAfterSeconds: Optional[float]) -> float:
        if retryAfterSeconds is not None:
            return min(retryAfterSeconds + 1, self.maxBackoff * 2)
        return min(self.baseBackoff * (2 ** (attemptNumber - 1)), self.maxBackoff) + random.uniform(0, 2)

    def _callProvider(self, state: ProviderState, role: str, systemPrompt: str, userPrompt: str,
                      temperature: float, maxTokens: int) -> str:
        self._checkSoftLimits(state)
        if self.maxTokensCap:
            maxTokens = min(maxTokens, self.maxTokensCap)
        for attemptNumber in range(1, self.maxRetries + 1):
            self._waitForMinimumInterval(state)
            startTime = time.time()
            state.lastCallTime = startTime
            try:
                response = self._sendRequest(state, systemPrompt, userPrompt, temperature, maxTokens)
            except requests.exceptions.Timeout:
                logger.warning("[%s] TIMEOUT after %ss (attempt %d/%d)", state.name, self.requestTimeout,
                               attemptNumber, self.maxRetries)
                time.sleep(self._computeBackoffSeconds(attemptNumber, None))
                continue
            except requests.exceptions.RequestException as networkError:
                logger.warning("[%s] NETWORK ERROR: %s (attempt %d/%d)", state.name, networkError,
                               attemptNumber, self.maxRetries)
                time.sleep(self._computeBackoffSeconds(attemptNumber, None))
                continue

            if response.status_code == 200:
                return self._handleSuccess(state, role, response, time.time() - startTime)

            errorCategory = classifyHttpError(response.status_code, response.text)
            bodySnippet = response.text[:300].replace("\n", " ")
            logEvent("llmError", provider=state.name, status=response.status_code, category=errorCategory)

            if errorCategory == errorAuthFailed:
                self._disableProvider(state, f"AUTH FAILED (HTTP {response.status_code}) - check the API key. {bodySnippet}")
                raise ProviderExhaustedError(state.disabledReason)
            if errorCategory == errorQuotaExhausted:
                resetHintSeconds = parseTryAgainSeconds(response.text)
                if resetHintSeconds is not None and resetHintSeconds <= self.maxQuotaWaitSeconds:
                    state.cooldownUntil = time.time() + resetHintSeconds + 2
                    logger.warning("[%s] TOKEN/QUOTA LIMIT reached (HTTP %s). Provider paused for %.0fs, then used again. %s",
                                   state.name, response.status_code, resetHintSeconds, bodySnippet)
                    raise ProviderExhaustedError(f"{state.name}: paused {resetHintSeconds:.0f}s by a token limit")
                self._disableProvider(state, f"API LIMIT/QUOTA EXHAUSTED (HTTP {response.status_code}). {bodySnippet}")
                raise ProviderExhaustedError(state.disabledReason)
            if errorCategory == errorRequestTooLarge:
                state.failedCallCount += 1
                logger.error("[%s] REQUEST TOO LARGE for this model's per-minute token limit (HTTP %s). Lower llm.maxTokensCap, "
                             "shorten prompts (audit.maxFunctionSourceChars) or use a model/plan with a higher TPM. %s",
                             state.name, response.status_code, bodySnippet)
                raise LlmError(f"request too large for {state.name}")
            if errorCategory in (errorRateLimited, errorTransient):
                state.rateLimitHits += 1 if errorCategory == errorRateLimited else 0
                retryAfterHeader = response.headers.get("retry-after")
                retryAfterSeconds = float(retryAfterHeader) if retryAfterHeader and retryAfterHeader.replace(".", "", 1).isdigit() else None
                retryAfterSeconds = retryAfterSeconds if retryAfterSeconds is not None else parseTryAgainSeconds(response.text)
                waitSeconds = self._computeBackoffSeconds(attemptNumber, retryAfterSeconds)
                label = "RATE LIMITED" if errorCategory == errorRateLimited else "SERVER BUSY/ERROR"
                logger.warning("[%s] %s (HTTP %s). Waiting %.0fs, attempt %d/%d. %s", state.name, label,
                               response.status_code, waitSeconds, attemptNumber, self.maxRetries, bodySnippet)
                time.sleep(waitSeconds)
                continue
            state.failedCallCount += 1
            logger.error("[%s] BAD REQUEST (HTTP %s): %s", state.name, response.status_code, bodySnippet)
            raise LlmError(f"bad request to {state.name}: HTTP {response.status_code} {bodySnippet}")

        state.failedCallCount += 1
        state.cooldownUntil = time.time() + self.cooldownSeconds
        logger.error("[%s] RETRIES EXHAUSTED after %d attempts; provider cooling down for %ss", state.name,
                     self.maxRetries, self.cooldownSeconds)
        raise ProviderExhaustedError(f"{state.name}: retries exhausted (rate limit or network)")

    def _handleSuccess(self, state: ProviderState, role: str, response: requests.Response, durationSeconds: float) -> str:
        try:
            replyText, inputTokens, outputTokens = self._parseResponse(state, response.json())
        except (ValueError, KeyError, IndexError, TypeError) as parseError:
            state.failedCallCount += 1
            logger.error("[%s] Could not parse provider response: %s | body: %s", state.name, parseError,
                         response.text[:300])
            raise LlmError(f"unparseable response from {state.name}") from parseError
        state.callCount += 1
        state.inputTokens += inputTokens
        state.outputTokens += outputTokens
        logger.info("[%s] OK role=%s %.1fs tokens in/out=%d/%d (total calls %d)", state.name, role,
                    durationSeconds, inputTokens, outputTokens, state.callCount)
        logEvent("llmCall", provider=state.name, role=role, seconds=round(durationSeconds, 2),
                 inputTokens=inputTokens, outputTokens=outputTokens)
        if not replyText.strip():
            logger.warning("[%s] Empty reply text received", state.name)
        return replyText

    def _sendRequest(self, state: ProviderState, systemPrompt: str, userPrompt: str, temperature: float,
                     maxTokens: int) -> requests.Response:
        if state.apiType == "anthropic":
            return requests.post(
                f"{state.baseUrl}/v1/messages", timeout=self.requestTimeout,
                headers={"x-api-key": state.apiKey, "anthropic-version": "2023-06-01", "content-type": "application/json"},
                json={"model": state.model, "max_tokens": maxTokens, "temperature": temperature,
                      "system": systemPrompt, "messages": [{"role": "user", "content": userPrompt}]})
        if state.apiType == "openai":
            requestBody = {"model": state.model, state.maxTokensField: maxTokens, "temperature": temperature,
                           "messages": [{"role": "system", "content": systemPrompt}, {"role": "user", "content": userPrompt}]}
            requestBody.update(state.extraRequestFields)
            return requests.post(f"{state.baseUrl}/chat/completions", timeout=self.requestTimeout,
                                 headers={"Authorization": f"Bearer {state.apiKey}", "content-type": "application/json"},
                                 json=requestBody)
        if state.apiType == "gemini":
            return requests.post(
                f"{state.baseUrl}/models/{state.model}:generateContent", timeout=self.requestTimeout,
                headers={"x-goog-api-key": state.apiKey, "content-type": "application/json"},
                json={"systemInstruction": {"parts": [{"text": systemPrompt}]},
                      "contents": [{"role": "user", "parts": [{"text": userPrompt}]}],
                      "generationConfig": {"temperature": temperature, "maxOutputTokens": maxTokens}})
        raise LlmError(f"unknown apiType '{state.apiType}' for provider {state.name}")

    def _parseResponse(self, state: ProviderState, responseJson: dict) -> Tuple[str, int, int]:
        if state.apiType == "anthropic":
            textParts = [block.get("text", "") for block in responseJson["content"] if block.get("type") == "text"]
            usage = responseJson.get("usage", {})
            return "".join(textParts), usage.get("input_tokens", 0), usage.get("output_tokens", 0)
        if state.apiType == "openai":
            usage = responseJson.get("usage", {})
            return (responseJson["choices"][0]["message"].get("content") or "",
                    usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0))
        if state.apiType == "gemini":
            parts = responseJson["candidates"][0]["content"]["parts"]
            usage = responseJson.get("usageMetadata", {})
            return ("".join(part.get("text", "") for part in parts),
                    usage.get("promptTokenCount", 0), usage.get("candidatesTokenCount", 0))
        raise LlmError(f"unknown apiType '{state.apiType}'")
