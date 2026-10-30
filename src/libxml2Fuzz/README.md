# Interconnected LLM-driven 3-engine fuzzing for libxml2

Goal: find NEW bugs (crashes, leaks, UB, hangs, memory blowups, logic errors) in libxml2.
Rule of the system: an LLM may *suggest*; only a deterministic check (compiler, sanitizer, oracle, standalone reproducer) may *confirm*.

## Architecture

```
 Hypothesis sources (4)                       Engines (3)                         Judges
 apiGap  (under-used API)  --\            1. AUDIT: LLM reads function            sanitizers
 pastFix (past fixes ->        >-- store -->    -> multi-LLM vote -> PoC -> ASan   + LLM voting panel
          siblings, incomplete)           2. DIFFERENTIAL: tricky XML vs expat    + standalone-repro checklist
 commitStream (new commits)               +  self-consistency (round-trip,
 staticAnalyzer (clang --analyze)            push-vs-oneshot, reader-vs-DOM)
                                          3. HARNESS: LLM writes libFuzzer harness
                                             -> gates -> coverage feedback -> long fuzz
```

Interconnections (this is the research contribution):
1. Audit suspicion that is plausible but has no triggering PoC  -> targeted fuzz harness (Engine 3).
2. Long-fuzzing coverage gaps                                    -> new hypotheses for the audit (Engine 1).
3. Differential disagreement confirmed by spec vote              -> root-cause hypothesis for the audit (Engine 1).
4. Every crash from every engine                                 -> same triage + harness-misuse voting.

## Setup (on each machine)

```bash
sudo apt install clang llvm cmake git python3-pip      # llvm gives llvm-profdata / llvm-cov
pip install -r requirements.txt
```
* **LLVM tools:** the program auto-detects versioned installs (e.g. `/usr/lib/llvm-18/bin/llvm-cov`, `llvm-cov-18`, Homebrew). Run `python main.py check`; if a tool is still reported missing, set `toolchain.llvmCov` / `toolchain.llvmProfdata` in `config/settings.json` to the full path (find it with `ls /usr/lib/llvm-*/bin | grep -E "llvm-(cov|profdata)"`). Keep clang and llvm tools on the SAME version.
* **LLM providers (Groq, default config):** all three entries use `apiType: "openai"` and `baseUrl: https://api.groq.com/openai/v1` (the `/openai` part is required). The three names (`groqA/B/C`) are just labels for three different Groq models, so voting uses different model families. One Groq key works for all three: `export GROQ_API_KEY=gsk_...` (read via `apiKeyEnv`; nothing is written to disk). Check the exact model IDs your account can use: `curl -s https://api.groq.com/openai/v1/models -H "Authorization: Bearer $GROQ_API_KEY"`. Do NOT use classifier models such as `llama-prompt-guard-2-86m`; they cannot write text/code.
* Optional per-provider `extraRequestFields` (merged into the request body, e.g. a reasoning-effort setting for reasoning models) and `llm.maxTokensCap` (lowers every request's max output tokens; useful if Groq answers "request too large" for the per-minute token limit).
* Groq free-tier limits are per model and per organization (not per key), with per-minute AND per-day token caps. The logs show `RATE LIMITED` (waits and retries, honoring Groq's "try again in" hint), `REQUEST TOO LARGE`, and `API LIMIT/QUOTA EXHAUSTED` (daily cap: provider disabled for the rest of this run; re-run after the reset).
* Multi-machine: set `distribution.machineIndex` (0,1,...) and `distribution.machineCount` on each machine; hypotheses and components are sharded by index.

## Commands

```bash
python main.py check                  # toolchain + which LLM providers are ready
python main.py setup                  # clone libxml2, build asanUbsan + coverage variants
python main.py baseline --hours 24    # DAY 1: upstream harnesses fuzz in the background
python main.py discover               # 4 hypothesis sources -> database   (needs baseline corpus for a meaningful gap map)
python main.py audit                  # Engine 1
python main.py differential           # Engine 2
python main.py harness                # Engine 3: generate + validate harnesses for API gaps
python main.py fuzz --hours 8         # long fuzzing with scheduler, plateau rule and crash triage
python main.py all --hours 4 --cycles 3
python main.py status
```
Recommended order: `setup` -> `baseline` (leave running a few hours) -> `discover` -> `audit` / `differential` / `harness` -> `fuzz`.

## Logs (all under work/logs)
* `fuzz.log`   everything (DEBUG), rotating.  `errors.log`  warnings and errors only.
* `events.jsonl`  one JSON line per metric event (llmCall, hypothesisCreated, voteResult, pocTriggered, harnessGateFailed, coverageRound, fuzzChunk, findingRecorded...). Use it to build the tables of the paper.
* LLM problems are explicit: `RATE LIMITED ... Waiting Ns`, `API LIMIT/QUOTA EXHAUSTED`, `AUTH FAILED - check the API key`, `PROVIDER DISABLED`, `ALL LLM PROVIDERS ARE EXHAUSTED` (work stays in the DB; re-run the same command later), plus a per-provider usage summary (calls, tokens, rate-limit hits).

## Output
Candidate findings land in `work/findings/<signature>/` with `report.md`, the reproducer and the evidence. **A candidate is not a bug until you finish the checklist in report.md** (standalone reproducer with documented API, re-test on latest master, check issue tracker/CVEs, read the API docs).

## What was tested (honestly)
Tested in a sandbox against current libxml2 master with a SCRIPTED FAKE LLM (no real API calls):
* source indexer (2,916 functions, 1,413 public API declarations), cmake builds (asanUbsan, coverage), harness/oracle compilation;
* Engine 1 path with a PoC that triggers ASan and one that runs clean -> targeted harness; harness gates, coverage loop, seeds/dictionary;
* Engine 2 oracle program and campaign; crash triage (reproduce, minimize, vote, report, de-duplicate); scheduler; upstream baseline harness build (10 of 12 build; `lint` and `testFuzzer` do not and are skipped with a warning).

NOT tested with real models: prompt quality, `pastFix`, `commitStream` and `staticAnalyzer` sources end-to-end, MSan and 32-bit variants. Expect to tune prompts in `src/prompts/promptLibrary.py` once real keys are attached.

## Known limitations
* `xmlMemSetup()` (allocation-failure injection) is deprecated in recent libxml2; if removed, adapt `src/templates/fuzzAllocator.h`.
* The Groq request/response shape and error handling were NOT tested against the live Groq API (the build sandbox cannot reach it); only unit-tested with Groq-style error messages. Model IDs on Groq change over time; verify them with the `/models` call above.
* Harness-bug false positives are the main risk. Example from development: the hand-written reference harness first reported a use-after-free on master that was really a harness mistake (prefixed attribute bound to an ancestor namespace, node later moved without `xmlReconciliateNs`). The voting + checklist exist for exactly this reason.
* The system finds candidates; novelty must always be verified against upstream.
