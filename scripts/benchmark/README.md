# Accuracy benchmark

The accuracy benchmark (see `GLOSSARY.md`) analyses fixed inputs on the running dev stack and compares every vulnerability instance the API shows with an adjudicated verdict. It prints precision, recall, the wrong and missed instances grouped by cause, the knowledge dump and the input commits.

It runs on demand only, never in CI.

## Running it

With the dev stack up (`make up`) and restored from the pinned knowledge dump, from the umbrella checkout:

```sh
sh scripts/benchmark/benchmark.sh run                      # every input
sh scripts/benchmark/benchmark.sh run --input cc-api       # one input
sh scripts/benchmark/benchmark.sh run --out /tmp/bench     # keep the recorded run in /tmp/bench
sh scripts/benchmark/benchmark.sh report /tmp/bench        # print the report again, offline
```

`run` logs in as the dev account, creates one project per input in its personal organization, uploads the input as an archive, runs the Default Analyzer and saves the API's answers in the output directory. `report` reads only that directory and the ground truth, so a recorded run can be re-judged after a ground-truth change without the stack.

Env: `API_URL` (default `http://localhost:3000`, the API without the `/api` prefix; use `https://localhost/api` with `CURL_CA` from the host), `LOGIN_EMAIL`, `LOGIN_PASSWORD`, `ANALYSIS_WAIT_SECONDS` (default 1200). The list is read with no filters, as the default view shows it; set `ACTIVE_FILTERS` (for example `[a,b]`) to send filters.

## Files

- `inputs.tsv`: one input per line: `name`, `repo` (a git checkout relative to the umbrella root, such as `api`), `commit` and `subdir` (the folder that becomes the archive root, `.` for the whole tree). The commit must be in the local checkout; `git -C <repo> fetch origin <commit>` if it is not. Add an input by appending a line and its ground-truth file.
- `fixtures/<name>/`: a synthetic fixture, a tiny project (manifest and lockfile, such as `package.json` and `package-lock.json`, or `composer.json` and `composer.lock`) for a case our own repositories lack. Its inputs line is `<name>`, `fixture`, `-` and `.` (or a folder inside the fixture). `run` archives the folder as it is in the checkout, so commit the folder, its inputs line and `ground-truth/<name>.tsv` together; the script needs no change.
- `knowledge-dump.txt`: the knowledge dump image the benchmark is pinned to. `run` refuses a stack whose `knowledge-restore` image (`.cloud/docker/docker-compose.yaml`, or `KNOWLEDGE_DUMP_IMAGE`) differs.
- `ground-truth/<name>.tsv`: one line per (canonical vulnerability, package, version): `vulnerability`, `package`, `version`, `verdict`, `cause` (`-` when none) and `evidence` (the record that supports the verdict).
- `benchmark.sh`: the runner. It reuses the login, upload, start and poll helpers of `.cloud/scripts/tests/fresh-install/lib.sh`.

## Verdicts

- `TP`: the instance is real. Shown, it counts as correct; not shown, as missed.
- `FP`: the instance is false. Shown, it counts as wrong; not shown, it is correctly absent.
- `LAG`: the right answer changed after the pinned dump was taken. The benchmark grades against the dump:
  - cause `withdrawn-after-snapshot`: the advisory was live in the dump, so it counts as `TP`;
  - cause `published-after-snapshot`: the dump has no record, so it is not expected, and if shown it is listed as unjudged.

An instance shown but absent from the ground truth is unjudged: it counts in neither precision nor recall and is listed so a maintainer can adjudicate it.

The report also counts the instances shown with severity None whose record has a CVSS vector or a GHSA severity, which should be 0. `run` reads the details of each instance shown as None for it; a run recorded before this check says "not recorded".

Precision is correct / (correct + wrong). Recall is found / expected, where expected counts every `TP` (and `LAG` withdrawn after the dump), including ones the run did not show.

## Ground truth

The cc-frontend and cc-api verdicts come from the 2026-11-18 measurement against the 2026-11-16 knowledge dump. Its baseline: cc-frontend shows 52 instances, 8 wrong; cc-api shows 76 instances, 11 wrong. The evidence link is the GHSA advisory when one matched, a GitHub advisory search when the verdict rests on a GHSA record or withdrawal, NVD for NVD-only matches and CIRCL's vulnerability lookup for GCVE-only matches. The cause tags:

| Cause                      | Verdict | Meaning                                                                              |
| -------------------------- | ------- | ------------------------------------------------------------------------------------ |
| `gcve-name-collision`      | FP      | the GCVE record is for another product with the same name                            |
| `gcve-unaffected-ignored`  | FP      | the CNA record lists the version as unaffected, and matching ignored it              |
| `no-veto-coarse-range`     | FP      | a coarse CNA range covers a version GHSA lists as fixed                              |
| `nvd-vendor-skipped`       | FP      | the NVD CPE names another vendor, such as a scoped package                           |
| `disputed-cve`             | FP      | the vendor disputes the CVE                                                          |
| `vendor-disputed`          | TP      | the vendor disputes the CVE; shown badged "Disputed", the grade leaves it out (#214) |
| `withdrawn-not-propagated` | FP      | GHSA withdrew the advisory, the CNA record is still published                        |
| `unreviewed-ghsa`          | TP      | true, though only the CNA record matched: its GHSA advisory is unreviewed            |
| `no-ghsa`                  | TP      | true, though only the CNA record matched: there is no GHSA advisory                  |
| `published-after-snapshot` | LAG     | published after the pinned dump                                                      |
| `withdrawn-after-snapshot` | LAG     | withdrawn after the pinned dump                                                      |

## Fixtures

| Fixture            | Case                                                                                                                                                              |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `npm-disputed-cve` | ejs 3.1.10 and CVE-2023-29827, which NVD scores 9.8 and the vendor disputes. Expected (`TP`), shown with the "Disputed" badge, and the grade leaves it out (#214) |

## Refreshing the knowledge

Moving to a newer knowledge dump is a deliberate step, never a side effect of a run:

1. Change `knowledge-dump.txt` and the stack's `knowledge-restore` image together, then `make reset CONFIRM=reset`.
2. Run the benchmark and re-check every verdict: `LAG` lines now have a settled answer (published ones become `TP` or `FP`, withdrawn ones `FP`), and new unjudged instances need a verdict with evidence.
3. Commit the dump pin and the ground-truth changes in one commit, saying which verdicts changed and why.
