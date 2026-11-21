# Knowledge dump

`make dump-knowledge` writes the knowledge dump and its dump manifest to `deployment/dump`. The dump ships as the
`codeclarityce/knowledge-dump:<date>` image (see [The knowledge dump image](#the-knowledge-dump-image)), which `make up`
restores into an empty knowledge database.
It works from a host stack and from the devcontainer (through the broker's `dump-knowledge` command).
The broker's code is baked into its image, so a change to its `dump-knowledge` command only takes effect after a
developer rebuilds the devcontainer.
Nothing is needed where you run it beyond the running stack: Go and Postgres tools come from its containers.

## Building the knowledge data

`make knowledge-update` runs the full update (`-knowledge -action update`) that a dump is built from, in the stack's
`service-package-follower` container with the key from `.cloud/env/.env.secrets`. On the host it runs
`.cloud/scripts/knowledge-update.sh` (an `NVD_API_KEY` in your environment wins over the file); in the devcontainer it goes
through the broker's `knowledge-update` command:

1. `cp .cloud/env/.env.secrets.example .cloud/env/.env.secrets` and set `NVD_API_KEY`. The file is gitignored; never put the key
   in `.env.dev` or `.env.makefile`, which are tracked.
2. `make up`, then `make knowledge-update`, then `make dump-knowledge`.

The broker reads only `NVD_API_KEY` from that file, at run time, and refuses to start if the file or key is missing, empty or
`!ChangeMe!`. It passes the key to `docker compose exec` as `-e NVD_API_KEY` with the value in docker's environment, so it is
not in the command line or the broker's logs. Neither the broker nor its client times out, and output streams as it runs.
The update takes 2 to 4 hours, and the broker runs one command at a time, so other `make` targets wait until it ends; read
logs from Loki meanwhile. If the client stops or its terminal closes, the update still runs to the end; the broker log records its exit status.

## Sources in the dump

The dump carries every knowledge source the update mirrors: `cwe`, `epss`, `friends_of_php`, `gcve`, `kev`, `licenses`,
`nvd` and `osv`, each with its row in `knowledge_source_sync` and its gate checks. `nvd`, `gcve`, `osv` and `kev` also keep
their source watermark in the `config` row (`nvd_last`, `gcve_last`, `osv_last`, `kev_last`), null until their first sync.

`kev` is the CISA Known Exploited Vulnerabilities catalog, fetched whole from
`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` on every update into the `kev`
table, one row per CVE. Entries the catalog drops are deleted. A catalog whose entries do not match its own `count`, or
with an entry that has no CVE, fails the source and leaves the stored entries untouched. Its gate checks are `kev.rows`,
`kev.last_outcome`, `kev.watermark` (48 hours by default) and `kev.upstream_total`, and a waiver can name them
(`WAIVE='kev.*'`). Offline instances get it only from the dump.

## What it does

1. Runs the read-only completeness gate (`-knowledge -action validate -read-only`) in `service-package-follower` and prints its JSON report.
   The gate expects the knowledge and config migrations found in `api/src/migrations`, passed as
   `KNOWLEDGE_EXPECTED_MIGRATIONS_KNOWLEDGE` and `_CONFIG`, so a stale list embedded in the service cannot pass or block a dump.
   Without an API checkout it falls back to that embedded list.
2. If the gate fails, it stops. Nothing in `deployment/dump` changes.
3. Otherwise it runs `.cloud/scripts/dump-knowledge-in-db.sh` inside the `db` container, with the gate report on stdin. The script:
   - dumps `knowledge` and `config` with `pg_dump -Fc` into a staging directory under `/dump`. `package` and `version` ship
     empty (schema only, `--exclude-table-data`), because packageFollower fills them on demand;
   - writes `knowledge-manifest.json` and `knowledge-manifest.sha256`;
   - only then replaces the previous `knowledge.dump`, `config.dump` and the manifest files.

Any failure leaves the previous dump untouched. `deployment/dump` is gitignored: dumps ship only as the knowledge dump image.

Dated dumps (`make dump-knowledge-dated`) are separate experiment files and are not gated.

### Waiving checks

When an upstream outage blocks a source and the rest of the build is worth publishing, waive that source's failing checks
explicitly, with a reason:

```sh
make dump-knowledge WAIVE='gcve.*' REASON='GCVE upstream unreachable during this build'
```

- `WAIVE` lists `<source>.<check>` or `<source>.*` patterns, comma-separated. Only checks of gated sources can be waived;
  `config.rows`, the migrations checks and `dated_restore` never can. `REASON` is required, one line, at most 300 characters.
- A waived check still fails in the report: it gains `"waived": true`, and the report gains
  `"waiver": {"reason": "...", "checks": [...]}` listing the checks the waiver let pass. Failures it does not cover still stop the dump.
- The manifest copies the report, so every install can see what the dump was published without. Rebuild without a waiver
  once the upstream recovers.
- On the host, `dump-knowledge.sh` passes `WAIVE` and `REASON` from its environment. In the devcontainer, the broker
  accepts them only on `dump-knowledge`, and checks their shape before passing them to the gate.

### Thresholds

| Variable                                             | Default | Meaning                                                                                 |
| ---------------------------------------------------- | ------- | --------------------------------------------------------------------------------------- |
| `KNOWLEDGE_GATE_UPSTREAM_TOLERANCE_PERCENT[_SOURCE]` | 1       | How far stored records may be from the recorded upstream total                          |
| `KNOWLEDGE_GATE_NVD_MISSING_CONFIGURATIONS_PERCENT`  | 0.1     | Share of Analyzed or Modified NVD CVEs that may lack configurations, as NVD serves some |
| `KNOWLEDGE_STALE_AFTER_HOURS_<SOURCE>`               | varies  | Oldest watermark the gate accepts                                                       |

## Files

| File                            | Contents                                        |
| ------------------------------- | ----------------------------------------------- |
| `knowledge.dump`, `config.dump` | `pg_dump -Fc` custom-format dumps, always whole |
| `knowledge-manifest.json`       | The dump manifest, below                        |
| `knowledge-manifest.sha256`     | `sha256sum -c` list of the dump files           |

Verify the files on disk with `sh deployment/scripts/restore-dump.sh verify` (`DUMP_DIR=deployment/dump`), or by hand with
`cd deployment/dump && sha256sum -c knowledge-manifest.sha256`.

Dumps are no longer split into parts: that existed only for the Git LFS file limit. A dump set holding `*.dump.part-*`
files is refused. If the dump grows past about 5 GB, the image spreads it across several layers instead.

## Manifest format 1

```json
{
  "format": 1,
  "build_date": "2026-11-10T12:00:00Z",
  "postgres_version": "18.6",
  "pg_dump_version": "pg_dump (PostgreSQL) 18.6",
  "files": [
    {
      "name": "knowledge.dump",
      "database": "knowledge",
      "size": 550000000,
      "sha256": "<sha256>"
    },
    {
      "name": "config.dump",
      "database": "config",
      "size": 2048,
      "sha256": "<sha256>"
    }
  ],
  "sources": [
    {
      "source": "nvd",
      "watermark": "2026-11-10T08:00:00+00:00",
      "last_outcome": "success",
      "upstream_total": 421910,
      "rows": 402754,
      "stored_records": 421910
    }
  ],
  "migrations": { "knowledge": ["<migration name>", "..."], "config": ["..."] },
  "gate": { "passed": true, "checks": [] }
}
```

| Field                                       | Meaning                                                                                                                         |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `format`                                    | Manifest format version. Readers must refuse a format they do not know                                                          |
| `build_date`                                | UTC time the dump started, RFC 3339                                                                                             |
| `postgres_version`                          | `SHOW server_version` of the database dumped                                                                                    |
| `pg_dump_version`                           | `pg_dump --version` that wrote the files. A restore needs `pg_restore` of this major version or newer                           |
| `files[]`                                   | One entry per database dump, in the order `knowledge`, `config`                                                                 |
| `files[].name`, `size`, `sha256`            | The dump file                                                                                                                   |
| `sources[]`                                 | One entry per row of `knowledge_source_sync`, sorted by source                                                                  |
| `sources[].watermark`                       | Source watermark in UTC, or null                                                                                                |
| `sources[].last_outcome`                    | `success` or `failure` of the source's last update                                                                              |
| `sources[].upstream_total`                  | Records upstream offered at the last successful update, or null                                                                 |
| `sources[].rows`                            | Active rows, the actual value of the gate's `<source>.rows` check                                                               |
| `sources[].stored_records`                  | Active and retired records, the actual value of the gate's `<source>.upstream_total` check; null for sources without that check |
| `migrations.knowledge`, `migrations.config` | Applied TypeORM migration names from each database's `migrations` table, oldest first                                           |
| `gate`                                      | The completeness gate report that passed, verbatim                                                                              |
| `gate.checks[].waived`                      | True on a failing check a waiver let pass                                                                                       |
| `gate.waiver`                               | Present only when checks were waived: the `reason` and the waived `checks`                                                      |

The manifest is not listed in `knowledge-manifest.sha256`, and neither file checksums itself. Manifests written before
dumps stopped splitting also carry `split_bytes` and `files[].parts[]` (empty); readers ignore them.

## Restoring

Every restore goes through `deployment/scripts/restore-dump.sh`, run inside the `db` container or, for the setup job,
inside the knowledge dump image:

| Path                                           | What runs                                                              |
| ---------------------------------------------- | ---------------------------------------------------------------------- |
| `make up` (`knowledge-restore` setup job)      | `restore-if-empty` from the knowledge dump image, before `migrate`     |
| `make restore-database` (umbrella, deployment) | `verify`, then `restore` for each database; stops at the first failure |

- `verify` checks every line of `knowledge-manifest.sha256` and that each dump matches `files[].sha256`. It refuses a
  manifest format other than 1, and any split dump part.
- `restore <dump> <database>` creates the database if it is missing, checks the dump against the manifest again, and runs
  `pg_restore`. A `pg_restore` error fails the restore.
- `restore-if-empty` is the knowledge restore setup job. If the knowledge database has any table, it restores nothing and
  succeeds, so a second `make up` keeps local knowledge updates. Otherwise it needs a manifest, runs `verify`, then restores
  `config` (unless config already has tables) and `knowledge`, each in one transaction, with `--no-owner --no-acl` and
  `--role` so their objects belong to `PG_CONFIG_ROLE` (default `cc_api`) and `PG_KNOWLEDGE_ROLE` (default `cc_knowledge`),
  the roles migrations run as. It leaves out the extensions and the pgbouncer auth function, which the Postgres init script
  already made. A dump failing its manifest, or a database it cannot read, fails the job, and the services waiting on
  `migrate` stay stopped; `make logs SERVICE=knowledge-restore` shows why.
- A stack whose knowledge database was migrated before it held any data has tables, so the job leaves it empty;
  `make reset CONFIRM=reset` wipes the stack and restores it again.
- A dump that is not in the manifest restores unverified.
- **Old dump layout.** Without `knowledge-manifest.json`, `restore` still restores whole dumps, with a warning that they are
  not verified. `restore-if-empty` refuses them.

## The knowledge dump image

`codeclarityce/knowledge-dump:<date>` holds `knowledge.dump`, `config.dump` and the manifest files in `/dump`, with
`restore-dump.sh`, on the same Postgres image as the stack's `db` (`.cloud/docker/knowledge-dump/Dockerfile`), so it
carries a matching `pg_restore`. Its default command is `restore-if-empty`; it reaches the database through `PGHOST` and
`POSTGRES_PASSWORD`. `<date>` is the manifest's `build_date` day.

The dev Compose file runs it as the `knowledge-restore` job, pinned to one tag; `migrate` waits for it to succeed. Docker pulls
and caches the image, so dev needs no separate download step. To ship a newer dump, publish its image and
change that tag.

The **Knowledge dump** workflow (`.github/workflows/knowledge-dump.yml`) builds and publishes it, so a published dump never
comes from a developer's machine. It runs every Monday and when dispatched by hand, only on `main` with `CI_RELEASE` set
to `true`, and every job runs in the `release` environment, which only `main` can use. It has no pull request trigger, so
no pull request run can read the environment's secrets. Its jobs:

1. **update and dump**: starts an empty Postgres (the knowledge dump image's base, with the deployment init script) and a
   RabbitMQ, migrates every database with the API image built from the `api` submodule, builds the knowledge tooling from
   `backend/services/knowledge` in that service's pinned Go image, and runs the full update (`-knowledge -action update`)
   with `NVD_API_KEY` from the environment. Update failures are only warnings: the completeness gate runs next, as
   `make dump-knowledge` runs it (same expected API migrations), and if it fails the run stops and nothing is published.
   Otherwise `dump-knowledge-in-db.sh` dumps knowledge and config with their manifest. A manual run's `waive` and `reason`
   inputs are the gate's `WAIVE` and `REASON`, recorded in the manifest's `gate.waiver`; scheduled runs waive nothing.
2. **image**: verifies the dump set against its manifest, refuses a dump from another Postgres major version than the
   image's, builds the image for amd64 and arm64, pushes it under a tag that must not exist yet, and attests its build
   provenance on Docker Hub.
3. **prune old tags**: `.cloud/scripts/prune-knowledge-dump-tags.sh` keeps every dated tag from the 8 weeks up to the newest
   one (so manual builds never push weekly ones out), every tag that the `docker-compose.yaml` asset of any
   `CodeClarityCE/deployment` release names, and the tag `.cloud/docker/docker-compose.yaml` on `main` names. It deletes every
   other dated tag through the Docker Hub API. Tags that are not dates are left alone. If any of those Compose files cannot be
   read, it deletes nothing and fails.

The `release` environment needs `NVD_API_KEY`, and `DOCKERHUB_USERNAME` with a `DOCKERHUB_TOKEN` that can read, write
and delete (pruning deletes tags). Without `NVD_API_KEY` the update still runs, at NVD's lower rate.

A run has no way to publish a dump built elsewhere: during an upstream outage, dispatch it with a waiver instead.

## Tests

`sh .cloud/scripts/tests/dump-knowledge.test.sh` runs the host `dump-knowledge.sh` with a stand-in `docker`.
`sh .cloud/scripts/tests/dump-knowledge-in-db.test.sh` runs the in-container script with stand-in `pg_dump` and `psql` (needs `jq`).
`sh .cloud/scripts/tests/restore-dump.test.sh` restores dump sets made by that script, refuses damaged ones, and covers
`restore-if-empty` (restore only into an empty knowledge database, and a failing manifest stopping the job), with stand-in
`pg_restore`, `psql`, `createdb` and `docker` (set `DEPLOYMENT_DIR` when the deployment submodule is checked out elsewhere).
`sh .cloud/scripts/tests/prune-knowledge-dump-tags.test.sh` runs the tag pruning against stand-in `gh` (deployment
releases and the dev Compose file on `main`) and `curl` (Docker Hub).
`sh .cloud/scripts/tests/knowledge-update.test.sh` runs the host `knowledge-update.sh` with a stand-in `docker`.
`sh .cloud/scripts/tests/reset.test.sh` checks that `make reset` refuses without `CONFIRM=reset`.
The broker commands are covered by `cd .devcontainer/broker && GOWORK=off go test ./...`.
