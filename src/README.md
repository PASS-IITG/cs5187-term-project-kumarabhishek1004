# `src/` — your code

Put **all your project code here** (tool, scripts, experiments, notebooks —
whatever your project produces).

Guidelines:

- Keep the code that produces every number in your paper in this folder, so a
  reader can reproduce your results.
- Add a short build/run note here (how to build, how to run, dependencies) —
  either extend this file or add your own `README`.
- Record exact versions of anything you depend on (compiler, tools, libraries)
  so results can be reproduced. These are the same versions you report in the
  paper's *Setup* subsection.
- If your project is an empirical study with no tool, put your analysis scripts
  and data-processing code here instead.

Do **not** commit large build outputs or binaries; commit the source and the
scripts that regenerate them.
