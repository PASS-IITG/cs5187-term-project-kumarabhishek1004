"""All LLM prompts in one place so they can be tuned without touching pipeline code."""
import json
from typing import Dict, List

systemSecurityResearcher = (
    "You are a senior C security researcher auditing the libxml2 XML library. You are precise, skeptical and concrete. "
    "You only claim bugs reachable through the PUBLIC libxml2 API with documented usage. "
    "When asked for JSON, reply with ONLY valid JSON and no commentary.")

systemCodeWriter = (
    "You are an expert C/C++ developer who writes libFuzzer harnesses and proof-of-concept programs for libxml2. "
    "Your code must compile with clang, follow libxml2 ownership rules exactly, and contain no commentary outside the code block.")

systemJudge = (
    "You are an impartial reviewer of bug reports in the libxml2 library. You decide whether a crash is a genuine library "
    "defect or a mistake in the test program (wrong ownership, double free, use after free of caller-owned data, "
    "undocumented call order, dangling pointers after moving nodes without xmlReconciliateNs, and so on). "
    "Reply with ONLY valid JSON.")


def buildPastFixAbstractionPrompt(commitSubject: str, diffText: str) -> str:
    return (
        f"A libxml2 commit fixed a bug.\nSubject: {commitSubject}\n\nDiff:\n{diffText}\n\n"
        "1. Abstract the bug into a reusable pattern.\n"
        "2. Propose a regular expression (grep -E syntax, no lookahead) that finds OTHER places in the C sources that could contain the "
        "same pattern.\n3. Say whether the fix itself might be incomplete (bypass via another path or input).\n\n"
        'Reply as JSON: {"patternName": str, "bugClass": str, "rootCause": str, "searchRegex": str, '
        '"incompleteFixIdeas": [{"functionName": str, "reasoning": str}]}')


def buildSiblingSearchPrompt(patternJson: Dict, grepMatches: str) -> str:
    return (
        f"Bug pattern learned from a past libxml2 fix:\n{json.dumps(patternJson, indent=1)}\n\n"
        f"Candidate code locations (file:line:text):\n{grepMatches}\n\n"
        "Pick up to 6 locations that most plausibly still contain the SAME flaw (an unfixed sibling). Skip safe ones.\n"
        'Reply as JSON list: [{"filePath": str, "functionName": str, "reasoning": str, "confidence": number 0-1}]')


def buildCommitReviewPrompt(commitSubject: str, diffText: str) -> str:
    return (
        f"Review this recent libxml2 commit for newly introduced bugs. New code has had little fuzzing.\n"
        f"Subject: {commitSubject}\n\nDiff:\n{diffText}\n\n"
        "List concrete suspected defects (memory safety, error paths and cleanup, integer overflow, logic errors, "
        'resource exhaustion). Reply as JSON list: [{"functionName": str, "bugClass": str, "reasoning": str, "confidence": number 0-1}] '
        "or [] if the change looks safe.")


def buildStaticWarningTriagePrompt(warningText: str, functionSource: str) -> str:
    return (
        f"A static analyzer reported:\n{warningText}\n\nFunction source:\n{functionSource}\n\n"
        "Is this warning likely a REAL bug reachable via the public API? "
        'Reply as JSON: {"isLikelyReal": bool, "bugClass": str, "reasoning": str, "confidence": number 0-1}')


def buildSuspicionPrompt(functionSource: str, declaration: str, callers: str, hypothesisDescription: str) -> str:
    return (
        f"Hypothesis to investigate: {hypothesisDescription}\n\nFunction under audit:\n{functionSource}\n\n"
        f"Public declaration (if any): {declaration or 'internal function'}\n\nSome callers:\n{callers or 'none found'}\n\n"
        "Decide whether a real, triggerable bug exists. Think about error paths (allocation failure), integer overflow before "
        "allocation, NULL handling, stale pointers after unlink/reparent, double free, bounds, infinite loops.\n"
        'Reply as JSON: {"isPlausible": bool, "bugClass": str, "triggerScenario": str, "publicApiSequence": [str], '
        '"requiredInput": str, "reasoning": str, "confidence": number 0-1}')


def buildVoteQuestionForSuspicion() -> str:
    return ("Is the suspected bug below plausible AND triggerable through the public libxml2 API with documented usage? "
            "Vote yes only if you can see a concrete trigger path.")


def buildPocPrompt(suspicionJson: Dict, functionSource: str, declaration: str) -> str:
    return (
        f"Write a minimal standalone C program that triggers this suspected libxml2 bug under AddressSanitizer/UBSan.\n\n"
        f"Suspicion:\n{json.dumps(suspicionJson, indent=1)}\n\nRelevant code:\n{functionSource}\nDeclaration: {declaration}\n\n"
        "Rules: only public libxml2 API, correct ownership, deterministic, finishes in under 10 seconds, int main(void), "
        "no external files (use xmlReadMemory or /tmp), no printing besides what helps diagnosis. If the bug needs an allocation failure, "
        'use xmlMemSetup() with a wrapper that fails the N-th allocation. Reply with ONE ```c code block only.')


def buildPocRepairPrompt(previousCode: str, problemKind: str, outputText: str) -> str:
    return (
        f"Your previous PoC did not work ({problemKind}).\n\nCode:\n```c\n{previousCode}\n```\n\nOutput:\n{outputText}\n\n"
        "Fix it so it compiles and actually triggers the suspected bug (or, if the bug cannot be triggered, change the trigger approach). "
        "Reply with ONE ```c code block only.")


def buildHarnessPrompt(componentName: str, apiDeclarations: List[str], referenceHarness: str, extraGoal: str) -> str:
    declarationText = "\n".join(apiDeclarations)
    return (
        f"Write a libFuzzer harness (C++17) for the libxml2 component '{componentName}'.\n{extraGoal}\n\n"
        f"Target API declarations (try to exercise as many as possible, in random order driven by fuzzer bytes):\n{declarationText}\n\n"
        "Requirements:\n"
        "- Single file; extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t*, size_t) and extern \"C\" int LLVMFuzzerInitialize(int*, char***).\n"
        "- #include <fuzzer/FuzzedDataProvider.h> and \"fuzzAllocator.h\"; call fuzzInstallAllocator() in LLVMFuzzerInitialize BEFORE xmlInitParser().\n"
        "- Use FuzzedDataProvider so bytes choose the API sequence, option flags and content. Arm allocation failure sometimes "
        "(fuzzArmAllocFailure) and ALWAYS call fuzzDisarmAllocFailure() before cleanup.\n"
        "- Free everything you own exactly once; respect libxml2 ownership (read headers carefully). No printing, no exit(), no files, no globals that grow.\n"
        "- Install a silent error handler with xmlSetGenericErrorFunc. Limit input size to a few KB.\n\n"
        f"Reference harness showing the expected style and ownership discipline:\n```cpp\n{referenceHarness}\n```\n"
        "Reply with ONE ```cpp code block only.")


def buildHarnessExtensionPrompt(currentHarness: str, apiDeclarations: List[str]) -> str:
    return (
        "You are the second author. Extend this harness so it also exercises the following APIs that it misses, "
        "keeping ownership rules correct and the code compiling. Do not remove existing coverage.\n\n"
        f"Missing APIs:\n{chr(10).join(apiDeclarations)}\n\nCurrent harness:\n```cpp\n{currentHarness}\n```\nReply with ONE ```cpp block only.")


def buildHarnessRepairPrompt(currentHarness: str, problemKind: str, outputText: str) -> str:
    return (
        f"This libFuzzer harness failed a quality gate: {problemKind}.\n\nOutput:\n{outputText}\n\n"
        f"Harness:\n```cpp\n{currentHarness}\n```\nFix the harness (it must compile with clang++ -std=c++17 against libxml2 headers). "
        "Remember that crashes in the first seconds usually mean an ownership mistake in the HARNESS. Reply with ONE ```cpp block only.")


def buildCoverageImprovementPrompt(currentHarness: str, uncoveredReport: str) -> str:
    return (
        "Coverage feedback from a short fuzzing run. These library functions are poorly covered; the lines below were never executed.\n\n"
        f"{uncoveredReport}\n\nExtend the harness so that fuzzer-chosen inputs and option flags can reach these lines. Keep all existing behavior.\n\n"
        f"Current harness:\n```cpp\n{currentHarness}\n```\nReply with ONE ```cpp block only.")


def buildSeedPrompt(componentName: str, apiDeclarations: List[str]) -> str:
    return (
        f"Create seed inputs and a fuzzing dictionary for a harness of libxml2 component '{componentName}' "
        f"that exercises: {', '.join(apiDeclarations[:12])}.\nSeeds are raw files fed to the harness (small, structurally interesting; "
        "XML/DTD/XSD/RelaxNG/XPath/catalog text as appropriate). Reply as JSON: "
        '{"seeds": [{"name": str, "content": str}], "dictionaryTokens": [str]} with at most 12 seeds and 60 tokens.')


def buildTrickyXmlPrompt(category: str, count: int) -> str:
    return (
        f"Generate {count} small but TRICKY XML documents in the category '{category}' that stress parser edge cases from the "
        "XML 1.0 / Namespaces specifications: some must be well-formed, some malformed in subtle ways. "
        'Reply as JSON list: [{"name": str, "xml": str, "expectedWellFormed": bool, "specReference": str}].')


def buildDisagreementPrompt(xmlText: str, evidence: str) -> str:
    return (
        f"Input document:\n{xmlText}\n\nObserved behavior:\n{evidence}\n\n"
        "According to the XML 1.0 and Namespaces in XML specifications, is libxml2's behavior WRONG? "
        'Reply as JSON: {"libxml2IsWrong": bool, "reasoning": str, "specSection": str}')


def buildCrashAdjudicationQuestion() -> str:
    return ("Is this crash a genuine defect in libxml2 (reachable with correct, documented API usage), "
            "rather than a mistake in the test program? Vote yes only if the test program's API usage looks correct.")


def buildVoteInstruction(question: str, evidence: str) -> str:
    return (f"{question}\n\nEvidence:\n{evidence}\n\n"
            'Reply as JSON: {"vote": "yes" or "no", "confidence": number 0-1, "reason": str}')
