# Writing style for research papers

Distilled from two earlier papers (ISEC 2027 *Compile More, Analyse More*,
FSE 2027 *Evaluating C/C++ Static Call Graphs*). Read this before writing
any section. `scripts/check.sh` checks the mechanical rules.

## 1. Language

1. **Simple English.** Short sentences, one idea each. If a sentence needs
   a semicolon, it is probably two sentences.
2. **No jargon, no buzzwords.** Use the plain word a practitioner uses.
   Banned words: *novel, powerful, seamless, leverage, utilize, robust,
   cutting-edge, state-of-the-art* (as praise), *paradigm, holistic,
   synergy, comprehensive, groundbreaking, revolutionary, unprecedented,
   significantly* (unless a statistical test backs it), *delve, crucial,
   pivotal, plethora, myriad, empower, unlock*, and *harness* as a verb ("harness
   the power"); a fuzzing *harness* (noun) is a technical term and fine. Write
   *use* not *utilize/leverage*, *show* not *demonstrate*, *help* not *facilitate*.
3. **"We" voice.** Present tense for what the tool does ("\tool records
   every command"). Past tense for what we did and measured ("We measured
   the default build").
4. **Plain connectives.** Write *for example*, *that is*, *such as* —
   not *e.g.*, *i.e.* in running text (fine inside parentheses/captions).
5. **Define once, reuse exactly.** A new term appears once as `\emph{term}`
   with a plain definition. Afterwards use the same word every time — no
   synonyms. Symbols live in `macros.tex`.
6. **Say what was measured, how, and what it means.** Never a number
   without its unit and its reference point ("55.5% of its code lines", not
   "much of the code").
7. **Honest limits.** When a tool fails or a step is not new, say so
   plainly: "We do not claim this step as new." / "CSA does not flag it,
   because ...". Limits end with "We leave this for future work."
8. **Answer the obvious objection yourself**, as a question paragraph:
   `\paragraph{Why not analyse all configurations at once?}` followed by a
   short honest answer.

## 2. Numbers

1. **Every number comes from a file.** A tool run or a script output kept
   in `data/` (or a path recorded in `HANDOFF.md` §Numbers with the source
   file). Never estimate, never round from memory.
2. Numbers not yet produced by the final tool are wrapped in `\num{}` (blue)
   until re-measured. Submission has zero `\num{}`.
3. Format: thousands `12{,}563`; percentages with one decimal `55.5\%`;
   ranges `8.6.0 to 8.8.0`; exact versions/commits of every subject.
4. The abstract, introduction and conclusion use **the same numbers**.
5. State the environment once (machine, OS, compiler and tool versions).
   Never mix numbers from two environments in one table without saying so.

## 3. Citations

1. Cite only entries verified against Crossref DOI metadata, the arXiv API
   or the publisher page. Fabricated citations cause desk rejection.
2. Web pages, CVEs, advisories: `@misc` with `url` and
   `note = {Accessed: YYYY-MM-DD}`; check the URL works.
3. Always `~\cite{}` (non-breaking space). Cite in the sentence that makes
   the claim. Quote a tool's own documentation when it states the problem
   (e.g. CodeQL "needs to invoke the required build system").
4. While anonymous, cite own work in the third person.

## 4. Structure, section by section

Section order (drop optional ones to fit the page limit):
Introduction → Background → *A First Look (optional)* → Problem → Approach →
*Implementation (optional)* → Evaluation → Discussion → Threats →
Related Work → Conclusion → Data Availability → Use of Generative AI.

**Title.** `Short Hook: Plain Description` ("Compile More, Analyse More:
Finding Build Configurations That Let C/C++ Static Analysers See the Most
Code"). Keep 2–3 alternatives as comments in `main.tex`.

**Abstract** (one paragraph, no citations): problem in 2–3 sentences →
one real case with an exact number → "We present \tool." + what it does →
results with numbers → one lesson the work taught.

**Introduction**, one job per paragraph:
1. A concrete scenario the reader knows ("Suppose you want to run a static
   analyser on a C library you have just cloned.").
2. The known problem and who works on it; end with where they stop
   ("These tools stop when the build succeeds.").
3. Our problem: "We focus on a second problem that starts where they stop: ..."
4. A **real** example (CVE, bug report, miscompilation) with exact numbers
   and a figure; then "This is not a single case." + a count.
5. Closest prior work and its precise gap ("However, they need ...").
6. "We present \tool" + numbered steps (`enumerate`), each one sentence.
7. First results with numbers and one lesson learned.
8. `\paragraph{Contributions.}` itemize, each item ending "(Section~\ref{})".

**Background.** Only what later sections need; one `\paragraph{}` per concept.

**A First Look** (strong when possible): "Before building a tool, we
checked whether the problem is large enough to matter." Exact
`\paragraph{How we count.}` definition, one table, preliminary numbers marked.

**Problem.** "We now state the problem precisely." Definitions with macros,
`\paragraph{Goal.}` with a formula, known complexity with citation, and a
`\paragraph{Why not ...?}`.

**Approach.** Overview figure first + the main idea in 2–3 sentences. One
`\subsection{Step N: ...}` per box in the figure. Inline lists as
(i)~...; (ii)~.... Say what is not new.

**Evaluation.** RQ list (plain questions a practitioner would ask, last one
usually cost) → Subjects (selection criteria as `enumerate`) → Baselines
(`description`, fair comparison: same budget) → Measurements (per RQ) →
Setup → one subsection per RQ. Show the table first, then read it. Every
finding goes in a numbered, labelled `observation` box: **one claim + the
number that supports it**. Refer back with `Observation~\ref{obs:...}`.

**Discussion.** Question paragraphs ("Is more code always better? No. ...").

**Threats.** Internal / External / Construct paragraphs. For each: the
threat, what we did (itemize the guards), what remains. Report
non-determinism and LLM run-to-run variation with numbers.

**Related Work.** One `\paragraph{Topic.}` per line of work, closest first
("Closest to us is the work of ..."). **Every paragraph ends with how we
differ** ("We share their goal, but ...").

**Conclusion.** Problem again with the key number; "We presented \tool,
which ..."; same numbers as the abstract; no new claims.

**Data Availability + Use of Generative AI.** Always present. Anonymous
mirror, no git history, scrubbed absolute paths. AI disclosure worded and
confirmed by the authors.

## 5. Figures, tables, listings

- Figures in TikZ (`figures/*.tex`), grayscale-safe (black lines,
  `black!6` fill), `\scriptsize` text, step numbers matching the text.
- **Captions state the lesson**, with the number, so a reader who reads only
  captions gets the paper. Table captions go above and explain every column.
- Tables: `booktabs` only, no vertical rules, numbers right-aligned, a total
  row after `\midrule`.
- Listings: real code trimmed with `...`, comments marking the bug via
  `escapechar=@`.
- References: `Section~\ref{sec:x}`, `Figure~\ref{fig:x}`,
  `Table~\ref{tab:x}`. Labels: `sec:`, `fig:`, `tab:`, `obs:`, `eq:`.

## 6. LaTeX hygiene

- One file per section in `sections/`; all notation in `macros.tex`.
- Tool name only through `\tool` (anonymised; final name later).
- `\todo{}` (red) for anything open. Submission has zero `\todo{}`.
- The CFP requirements sit as a comment block at the top of `main.tex`,
  with the URL and the date checked.
- `make check` must pass: no LaTeX errors, no undefined references or
  citations, no `\todo`/`\num`, no banned words, page limit met.
