# Accuracy benchmark

The accuracy benchmark (see `GLOSSARY.md`) analyses fixed inputs on the running dev stack and compares every vulnerability instance the API shows with an adjudicated verdict. It prints precision, recall, the wrong and missed instances grouped by cause, the knowledge dump and the input commits.

Its report runs on demand only, never in CI. The results gate (`scripts/results-gate`) reuses its `run` in CI to compare findings with expected results, not with verdicts.

## Running it

With the dev stack up (`make up`) and restored from the pinned knowledge dump, from the umbrella checkout:

```sh
sh scripts/benchmark/benchmark.sh run                      # every input
sh scripts/benchmark/benchmark.sh run --input cc-api       # one input
sh scripts/benchmark/benchmark.sh run --out /tmp/bench     # keep the recorded run in /tmp/bench
sh scripts/benchmark/benchmark.sh report /tmp/bench        # print the report again, offline
```

`run` logs in as the dev account, creates one project per input in its personal organization, uploads the input as an archive, runs the Default Analyzer and saves the API's answers in the output directory. `report` reads only that directory and the ground truth, so a recorded run can be re-judged after a ground-truth change without the stack.

Env: `API_URL` (default `http://localhost:3000`, the API without the `/api` prefix; use `https://localhost/api` with `CURL_CA` from the host), `LOGIN_EMAIL`, `LOGIN_PASSWORD`, `ANALYSIS_WAIT_SECONDS` (default 1200). The list is read with no filters, as the default view shows it, so instances the API hides by default (every source match contradicted by another source origin, or retired on all sources) are not shown and count as absent; set `ACTIVE_FILTERS` (for example `[a,b]`) to send filters.

## Files

- `inputs.tsv`: one input per line: `name`, `repo` (a git checkout relative to the umbrella root, such as `api`, or `.` for the umbrella), `commit`, `subdir` (the folder that becomes the archive root, `.` for the whole tree) and `workspaces` (the workspaces whose lists are read, comma-separated, `.` for the root). The commit must be in the local checkout; `git -C <repo> fetch origin <commit>` if it is not. A listed workspace that is a submodule at that commit gets the top-level files (manifests and lockfiles) of the submodule's checkout at its pinned commit, which keeps the upload under the API's 25 MB limit. Add an input by appending a line and its ground-truth file.
- `fixtures/<name>/`: a synthetic fixture, a tiny project (manifest and lockfile, such as `package.json` and `package-lock.json`, or `composer.json` and `composer.lock`) for a case our own repositories lack. The files are stored with a `.fixture` suffix (`package.json.fixture`) so GitHub does not scan them ([ADR 0014](../../docs/adr/0014-fixtures-are-stored-renamed.md)); `.cloud/scripts/tests/fixture-names.test.sh` fails on a real-named one. Its inputs line is `<name>`, `fixture`, `-`, `.` (or a folder inside the fixture) and `.`. `run` archives the folder as it is in the checkout, with the suffix removed, so commit the folder, its inputs line and `ground-truth/<name>.tsv` together; the script needs no change.
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

The cc-frontend and cc-api verdicts come from the 2026-11-18 measurement against the 2026-11-16 knowledge dump. cc-umbrella is the umbrella at the commit that pins those same api and frontend commits. Its root `pnpm-lock.yaml` makes it one pnpm workspace with `api` and `frontend` members, resolved from that lockfile rather than the submodules' own. Its ground truth is the cc-frontend and cc-api verdicts for the package versions that lockfile also resolves. That leaves out the eight undici 8.10.2 lines (the root lockfile has undici 8.12.4). Instances in the 30 versions only the root lockfile has show as unjudged until they are adjudicated. Its baseline: cc-frontend shows 52 instances, 8 wrong; cc-api shows 76 instances, 11 wrong. The evidence link is the GHSA advisory when one matched, a GitHub advisory search when the verdict rests on a GHSA record or withdrawal, NVD for NVD-only matches and CIRCL's vulnerability lookup for GCVE-only matches. The cause tags:

| Cause                      | Verdict | Meaning                                                                   |
| -------------------------- | ------- | ------------------------------------------------------------------------- |
| `gcve-name-collision`      | FP      | the GCVE record is for another product with the same name                 |
| `gcve-unaffected-ignored`  | FP      | the CNA record lists the version as unaffected, and matching ignored it   |
| `no-veto-coarse-range`     | FP      | a coarse CNA range covers a version GHSA lists as fixed                   |
| `nvd-vendor-skipped`       | FP      | the NVD CPE names another vendor, such as a scoped package                |
| `disputed-cve`             | FP      | the vendor disputes the CVE                                               |
| `withdrawn-not-propagated` | FP      | GHSA withdrew the advisory, the CNA record is still published             |
| `unreviewed-ghsa`          | TP      | true, though only the CNA record matched: its GHSA advisory is unreviewed |
| `no-ghsa`                  | TP      | true, though only the CNA record matched: there is no GHSA advisory       |
| `published-after-snapshot` | LAG     | published after the pinned dump                                           |
| `withdrawn-after-snapshot` | LAG     | withdrawn after the pinned dump                                           |

## Fixtures

| Fixture                   | Case                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `npm-disputed-cve`        | ejs 3.1.10 and CVE-2023-29827, which NVD scores 9.8 and the vendor disputes. Judged wrong (`FP`, `disputed-cve`) like the measurement judged ejs 5.0.2; #214 still shows it badged "Disputed" and leaves it out of the grade                                                                                                                                                                                                      |
| `npm-cna-backport`        | nanoid 3.3.18 and CVE-2026-67214. The CNA record lists affected 0 to 5.1.16 and 0 to 3.3.16, and 3.3.16 unaffected as the fix backported to the 3.x line. Judged wrong (`FP`, `gcve-unaffected-ignored`) like the measurement judged it in cc-api; #225 drops it                                                                                                                                                                  |
| `npm-gcve-name-collision` | sirv 3.0.2 and negotiator 0.6.3, which share their names with GCVE records for other products (`FP`, `gcve-name-collision`), and uri-js 4.4.1, whose CNA-only GCVE records are real (`TP`, `unreviewed-ghsa`). #224 drops the first and keeps the second                                                                                                                                                                          |
| `npm-nvd-vendor-clash`    | passport 0.7.0 and @fastify/passport 2.2.0, with CVE-2023-29019 and CVE-2023-29020, whose NVD CPEs name the `fastify` vendor's `passport`. Judged wrong (`FP`, `nvd-vendor-skipped`) on passport like the measurement judged it in cc-api, and right (`TP`) on @fastify/passport; #226 drops the passport ones and keeps the scoped ones                                                                                          |
| `npm-ghsa-backport-fix`   | brace-expansion 1.1.18. The CNA records of CVE-2026-13149 and CVE-2026-14257 cover every version through 5.0.6 and 5.0.7, while GHSA lists 1.1.16 and 1.1.17 as the fixes backported to the 1.x line (`FP`, `no-veto-coarse-range`). CVE-2026-102276 to CVE-2026-102278 affect 1.1.18 in GHSA too (`TP`). #222 hides the first two as contradicted and keeps the other three                                                      |
| `npm-ghsa-withdrawn`      | sprintf-js 1.0.3 and CVE-2026-97058, whose GHSA advisory GHSA-hp3w-g68c-fv3c was withdrawn on 2026-10-22 and whose NVD record is rejected, while the CNA's GCVE record is still published (`FP`, `withdrawn-not-propagated`). #222 hides it as contradicted                                                                                                                                                                       |
| `composer-smarty-php-jwt` | smarty/smarty v4.3.0, which GHSA and the CNA both list as affected by CVE-2023-28447, CVE-2024-35226, CVE-2026-62992 and CVE-2026-62993 (`TP`), and firebase/php-jwt 6.11.0 with CVE-2025-45769, whose vendor disputes it (`FP`, `disputed-cve`). The Composer case: the four smarty instances guard recall, the php-jwt one the Disputed badge. The lockfile writes `v4.3.0`; the ground truth uses `4.3.0`, as the API shows it |

## Refreshing the knowledge

Moving to a newer knowledge dump is a deliberate step, never a side effect of a run:

1. Change `knowledge-dump.txt` and the stack's `knowledge-restore` image together, then `make reset CONFIRM=reset`.
2. Run the benchmark and re-check every verdict: `LAG` lines now have a settled answer (published ones become `TP` or `FP`, withdrawn ones `FP`), and new unjudged instances need a verdict with evidence.
3. Commit the dump pin and the ground-truth changes in one commit, saying which verdicts changed and why.
