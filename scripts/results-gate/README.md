# Results gate

The results gate (see `GLOSSARY.md` and [ADR 0021](../../docs/adr/0021-a-results-gate-is-the-correctness-test-for-analyzers.md)) analyses fixed fixture projects with the Default Analyzer on a real instance restored from the accuracy benchmark's pinned knowledge dump, reads the findings through the API, and compares them with the expected results in `expected/`. It compares every result type users see: vulnerability instances, SBOM entries and licences. Any finding that appeared or disappeared fails it, and the log lists each one.

Its inputs are pinned: the fixtures, the knowledge dump, and the registry data the package follower would otherwise fetch live. The dump ships the `package` and `version` tables empty, and the licence finder, the vulnerability finder and the API read them, so before the analyses `run` loads the rows recorded in `registry/` for the fixtures' packages, dated now, which the follower skips as fresh. An upstream release therefore cannot change the gate's results ([#402](https://github.com/CodeClarityCE/codeclarity-dev/issues/402)).

Two guards make a live fetch fail the gate loudly:

- In CI the package follower is on an internal Docker network only (`docker-compose.yaml` here, merged over the trimmed stack with `STACK_OVERRIDE`), with just pgbouncer and RabbitMQ beside it, so it cannot reach any registry. A step checks that before the analyses (`stack.sh offline service-follower`).
- After the analyses, `run` checks every package of the run's SBOM in the knowledge database: one with no recorded row, or whose row the follower rewrote after the load, fails the gate and is named in the log. This also works on the dev stack, where the follower has network access.

The inputs cover every lockfile the analyzers read: npm (`npm-gcve-name-collision`), yarn v1 (`yarn-lodash-minimist`), pnpm (`pnpm-json5-semver`) and Composer (`composer-smarty-php-jwt`).

It runs in umbrella CI (the `results gate` job of `ci.yml`, part of the required `ci` check) on every pull request to `main` or `develop`, so on every submodule pointer bump, on pushes to `main` and `develop`, and nightly (`.github/workflows/results-gate.yml`). On a pull request it first checks out the PR's branch in each submodule that has one of the same name, `develop` in the others ([ADR 0020](../../docs/adr/0020-keep-submodules-and-test-same-named-branches-together.md), `scripts/same-named-branches.sh`), so a cross-repo change is gated as one unit before its pointers are bumped.

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

## When the fixtures' packages change

A fixture that gains a package, or a deliberate refresh of the registry data, needs new recorded rows. Refreshing them is a reviewed change like `update`: the diff of `registry/` shows what upstream changed, next to any change in findings.

```sh
sh scripts/results-gate/gate.sh record      # on the dev stack: delete the packages' rows, analyse on live registries, record
git diff scripts/results-gate/registry
sh scripts/results-gate/gate.sh update      # only if the findings changed on purpose
```

`record` analyses on the live registries with the follower of the running stack, which on the dev stack is your checkout's code, not the submodule pointers; check the recorded rows against CI. With a recorded run, `record DIR` records the stack's rows of that run's packages without analysing again.

## Commands

```sh
sh scripts/results-gate/gate.sh run [--out DIR]   # load registry/, analyse the inputs on the running stack, record in DIR, check
sh scripts/results-gate/gate.sh check DIR         # compare a recorded run with expected/
sh scripts/results-gate/gate.sh update [DIR]      # rewrite expected/ from a recorded run, or from a new run on registry/
sh scripts/results-gate/gate.sh record [DIR]      # rewrite registry/ from the stack's rows of a recorded run, or of a new live run
```

`run`, and `update` and `record` without a directory, use `scripts/benchmark/benchmark.sh run`, so they take the same env (`API_URL`, `CURL_CA`, `LOGIN_EMAIL`, `LOGIN_PASSWORD`, `ANALYSIS_WAIT_SECONDS`) and refuse a stack on another knowledge dump. `check` and `update` refuse a recorded run on another dump than `scripts/benchmark/knowledge-dump.txt`.

`run`, `update` and `record` also read and write the stack's `knowledge` database through `RESULTS_GATE_PSQL`, a command that runs the SQL on its stdin and prints one line per row. The default is `psql -X -q -t -A -v ON_ERROR_STOP=1 -d knowledge`, which takes the usual `PGHOST`, `PGUSER` and `PGPASSWORD`; CI uses `sh .cloud/scripts/tests/real-stack/stack.sh psql knowledge`. Loading replaces the stack's rows of the recorded packages, so run it on a dev or throwaway stack only.

## Files

- `registry/<language>/<package>.json`: the recorded `package` row of each package the gate's analyses send the follower, with its `version` rows under `versions`, written by `record` with sorted keys. The load dates them now; ids and times are not recorded.
- `docker-compose.yaml`: the gate's Compose file for CI, which leaves the follower no outbound network.
- `inputs.txt`: the accuracy benchmark inputs (`scripts/benchmark/inputs.tsv`) the gate analyses, one name per line. Add one by appending its name and running `record`, then `update`; a new fixture first needs its folder, inputs line and ground truth in the benchmark (see `scripts/benchmark/README.md`).
- `expected/<input>/<result type>.tsv`: the expected results of one input, written by `update`: a header, then one line per finding, sorted with `LC_ALL=C sort -u`.
  - `vulnerabilities.tsv`: `workspace`, `vulnerability`, `package` and `version`, one line per vulnerability instance shown in the default view of the list.
  - `sbom.tsv`: `workspace`, `ecosystem`, `package` and `version`, one line per SBOM entry (the `sbom` endpoint).
  - `licences.tsv`: `workspace`, `licence`, `package` and `version`, one line per package of each licence in the licence list (the `licenses` endpoint).

A recorded run holds the API's pages of each list (`<input>.pages/`, `<input>.sbom/`, `<input>.licences/`); `check` and `update` refuse a run that lacks one, such as one recorded before the gate compared it.

A new knowledge dump changes findings, so the pinned dump and the expected results are updated in one reviewed commit (see "Refreshing the knowledge" in `scripts/benchmark/README.md`).
