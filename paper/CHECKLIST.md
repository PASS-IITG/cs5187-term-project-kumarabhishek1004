# Before submission

Run `make check` first; it covers the items marked (auto).

The **red `FOCUS` boxes** in the sections mark the five graded must-haves:
Motivating Example (intro), Workflow (approach), Research Questions
(evaluation), Related Work, and Threats to Validity. Write each section,
then delete its `\focus{...}` line (keep the section). A finished report has
zero red `\focus` and zero `\todo`.

## Content
- [ ] Abstract, introduction and conclusion give the same numbers
- [ ] Every number is in HANDOFF.md §4 with its source file
- [ ] No `\num{}` and no `\todo{}` left (auto)
- [ ] Every RQ has a subsection, a table/figure and at least one Observation
- [ ] Each Related Work paragraph ends with how we differ
- [ ] Threats: internal, external, construct
- [ ] Limits stated plainly, with "future work" where relevant
- [ ] Motivating example is real and its numbers are measured

## Style (STYLE.md)
- [ ] No banned words (auto), few sentences over 35 words (auto)
- [ ] Every term defined once and used the same way afterwards
- [ ] Captions state the lesson; table captions explain every column
- [ ] Figures readable in grayscale

## Citations
- [ ] Every entry verified (Crossref / arXiv / publisher); date in references.bib
- [ ] Web sources have `Accessed:` dates and working URLs
- [ ] No undefined citations (auto)

## Venue rules
- [ ] Right document class and options (CFP block in main.tex re-checked)
- [ ] Page limit (auto, check by eye)
- [ ] Anonymous: no names, no identifying URLs/paths (auto), self-citation
      in third person, no acknowledgments
- [ ] Data availability: anonymous mirror, no git history, scrubbed paths
- [ ] Generative-AI disclosure confirmed by every author
- [ ] CCS concepts and keywords filled (ACM)
- [ ] PDF fonts embedded (`pdffonts main.pdf`), uploaded PDF opened once
