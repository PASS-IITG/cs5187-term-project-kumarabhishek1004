# CS-5187 — Term Project

This repository is your starting point for the CS-5187 term project. It has two
parts:

```
paper/    the report, in FSE (ACM acmsmall) LaTeX format  ← write here
src/      your code (tool, scripts, experiments, data)     ← code here
```

Your project can be in **any** area of the course: static analysis, dynamic
analysis / testing, or software engineering more broadly (empirical studies,
program repair, refactoring, build systems, …). The template does not assume a
particular topic.

## What to do

1. **Put your code in `src/`.** Everything that produces a result or a number in
   your paper goes there, with a note on how to build and run it. See
   [`src/README.md`](src/README.md).
2. **Write your report in `paper/`.** Edit the section files in
   `paper/sections/`. Build the PDF with:
   ```sh
   cd paper
   make          # builds paper/main.pdf
   make check    # checks for leftover TODOs, banned words, undefined refs, page limit
   ```
3. **Address the five graded parts.** In `paper/`, each is flagged with a red
   `FOCUS` box that says what it must contain. Write the section, then **delete
   that `\focus{...}` line** (keep the section). The graded parts are:

   | Part | Where |
   |------|-------|
   | Motivating example | `sections/introduction.tex` |
   | Workflow | `sections/approach.tex` |
   | Research questions | `sections/evaluation.tex` |
   | Related work | `sections/related.tex` |
   | Threats to validity | `sections/threats.tex` |

4. **Finish clean.** A submittable report has **zero** red `\focus` and **zero**
   `\todo`, and `make check` passes. Use
   [`paper/CHECKLIST.md`](paper/CHECKLIST.md) before you submit.

## Rules that matter (see `paper/STYLE.md`)

- Every number in the paper comes from a real run of your code in `src/` — never
  invented or rounded from memory.
- The motivating example must be **real**, with exact numbers.
- Cite only papers you have verified; fabricated citations are not accepted.
- Write in plain, simple English.

## Submitting

Commit both your `src/` code and your `paper/` sources (not the built PDF — it is
gitignored). Make sure the repository builds from a clean checkout:

```sh
cd paper && make
```
