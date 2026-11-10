# Knowledge dump

`make dump-knowledge` writes the knowledge dump and its dump manifest to `deployment/dump`.
It works from a host stack and from the devcontainer (through the broker's `dump-knowledge` command).
Nothing is needed where you run it beyond the running stack: Go and Postgres tools come from its containers.

## What it does

1. Runs the read-only completeness gate (`-knowledge -action validate -read-only`) in `service-package-follower` and prints its JSON report.
2. If the gate fails, it stops. Nothing in `deployment/dump` changes.
3. Otherwise it runs `.cloud/scripts/dump-knowledge-in-db.sh` inside the `db` container, with the gate report on stdin. The script:
   - dumps `knowledge` and `config` with `pg_dump -Fc` into a staging directory under `/dump`;
   - splits any file larger than `SPLIT_BYTES` (default 1900 MiB, under GitHub's 2 GB Git LFS file limit) into parts and removes the whole file;
   - writes `knowledge-manifest.json` and `knowledge-manifest.sha256`;
   - only then replaces the previous `knowledge.dump`, `config.dump`, their parts and the manifest files.

Any failure leaves the previous dump untouched. `make dump-database` dumps `codeclarity` and then runs `make dump-knowledge`; `dump-db.sh` refuses `knowledge` and `config`.

Dated dumps (`make dump-knowledge-dated`) are separate experiment files and are not gated.

## Files

| File                                  | Contents                                                                                  |
| ------------------------------------- | ----------------------------------------------------------------------------------------- |
| `knowledge.dump`, `config.dump`       | `pg_dump -Fc` custom-format dumps, when not split                                         |
| `<db>.dump.part-aaa`, `part-aab`, ... | Parts of a split dump. `cat <db>.dump.part-*` rebuilds it: the suffixes sort in order     |
| `knowledge-manifest.json`             | The dump manifest, below                                                                  |
| `knowledge-manifest.sha256`           | `sha256sum -c` list of every file on disk: each unsplit dump, or each part of a split one |

Verify the files on disk with `cd deployment/dump && sha256sum -c knowledge-manifest.sha256`.
After rebuilding a split dump, compare its SHA-256 with `files[].sha256` in the manifest.

## Manifest format 1

```json
{
  "format": 1,
  "build_date": "2026-11-10T12:00:00Z",
  "postgres_version": "18.6",
  "pg_dump_version": "pg_dump (PostgreSQL) 18.6",
  "split_bytes": 1992294400,
  "files": [
    {
      "name": "knowledge.dump",
      "database": "knowledge",
      "size": 2400000000,
      "sha256": "<sha256 of the whole file>",
      "parts": [
        {
          "name": "knowledge.dump.part-aaa",
          "size": 1992294400,
          "sha256": "<sha256>"
        },
        {
          "name": "knowledge.dump.part-aab",
          "size": 407705600,
          "sha256": "<sha256>"
        }
      ]
    },
    {
      "name": "config.dump",
      "database": "config",
      "size": 2048,
      "sha256": "<sha256>",
      "parts": []
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
| `split_bytes`                               | Largest part size used for splitting                                                                                            |
| `files[]`                                   | One entry per database dump, in the order `knowledge`, `config`                                                                 |
| `files[].name`, `size`, `sha256`            | The whole dump file, even when only its parts are on disk                                                                       |
| `files[].parts[]`                           | Empty when the file is not split. Otherwise every part in order, with its size and SHA-256                                      |
| `sources[]`                                 | One entry per row of `knowledge_source_sync`, sorted by source                                                                  |
| `sources[].watermark`                       | Source watermark in UTC, or null                                                                                                |
| `sources[].last_outcome`                    | `success` or `failure` of the source's last update                                                                              |
| `sources[].upstream_total`                  | Records upstream offered at the last successful update, or null                                                                 |
| `sources[].rows`                            | Active rows, the actual value of the gate's `<source>.rows` check                                                               |
| `sources[].stored_records`                  | Active and retired records, the actual value of the gate's `<source>.upstream_total` check; null for sources without that check |
| `migrations.knowledge`, `migrations.config` | Applied TypeORM migration names from each database's `migrations` table, oldest first                                           |
| `gate`                                      | The completeness gate report that passed, verbatim                                                                              |

The manifest is not listed in `knowledge-manifest.sha256`, and neither file checksums itself.

## Tests

`sh .cloud/scripts/tests/dump-knowledge-in-db.test.sh` runs the in-container script with stand-in `pg_dump` and `psql` (needs `jq`).
The broker command is covered by `cd .devcontainer/broker && GOWORK=off go test ./...`.
