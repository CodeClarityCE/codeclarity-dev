# Results gate

The results gate (see `GLOSSARY.md` and [ADR 0021](../../docs/adr/0021-a-results-gate-is-the-correctness-test-for-analyzers.md)) analyses fixed fixture projects with the Default Analyzer on a real instance restored from the accuracy benchmark's pinned knowledge dump, reads the findings through the API, and compares them with the expected results in `expected/`. Any finding that appeared or disappeared fails it, and the log lists each one.

It runs in umbrella CI (the `results gate` job of `ci.yml`, part of the required `ci` check) on every pull request to `main` or `develop`, so on every submodule pointer bump, on pushes to `main` and `develop`, and nightly (`.github/workflows/results-gate.yml`).

## When it fails

A failure means what users see changed. If the change is a bug, fix it. If it is intended, update the expected results in the same PR, so the reviewer sees the change in findings next to the code that caused it:

```sh
gh run download <run id> -n results-gate-run -D /tmp/results-gate   # the failed job's recorded run
sh scripts/results-gate/gate.sh update /tmp/results-gate
git diff scripts/results-gate/expected
```

Or regenerate from a fresh run on the dev stack (`make up`, restored from the pinned dump), which analyses the inputs first. The dev stack runs your checkout's code, not the submodule pointers, so check it against CI:

```sh
sh scripts/results-gate/gate.sh update
```

## Commands

```sh
sh scripts/results-gate/gate.sh run [--out DIR]   # analyse the inputs on the running stack, record in DIR, check
sh scripts/results-gate/gate.sh check DIR         # compare a recorded run with expected/
sh scripts/results-gate/gate.sh update [DIR]      # rewrite expected/ from a recorded run, or from a new run
```

`run` and `update` without a directory use `scripts/benchmark/benchmark.sh run`, so they take the same env (`API_URL`, `CURL_CA`, `LOGIN_EMAIL`, `LOGIN_PASSWORD`, `ANALYSIS_WAIT_SECONDS`) and refuse a stack on another knowledge dump. `check` and `update` refuse a recorded run on another dump than `scripts/benchmark/knowledge-dump.txt`.

## Files

- `inputs.txt`: the accuracy benchmark inputs (`scripts/benchmark/inputs.tsv`) the gate analyses, one name per line. Add one by appending its name and running `update`.
- `expected/<input>/<result type>.tsv`: the expected results of one input, written by `update`: a header, then one line per finding, sorted with `LC_ALL=C sort -u`. `vulnerabilities.tsv` holds `workspace`, `vulnerability`, `package` and `version`, one line per vulnerability instance shown in the default view of the list.

A new knowledge dump changes findings, so the pinned dump and the expected results are updated in one reviewed commit (see "Refreshing the knowledge" in `scripts/benchmark/README.md`).
