# Database connection pooling

All services/plugins/API connect through a **pgbouncer** transaction pooler (`PG_DB_HOST=pgbouncer`,
`PG_DB_PORT=6432`), never directly to Postgres. This multiplexes the many per-replica client pools
onto a small server-side connection set, so replica count no longer drives `max_connections`.

- **Per-instance pool bounds** are env-overridable: `DB_MAX_OPEN_CONNS` (default 15),
  `DB_MAX_IDLE_CONNS` (3), `DB_CONN_MAX_LIFETIME_SECONDS` (300), `DB_CONN_MAX_IDLE_SECONDS` (60)
  for the Go services/plugins (applied via `DatabaseConfig.ApplyPool` in
  `backend/utilities/boilerplates/`), and `PG_DB_POOL_MAX` (10) for each NestJS API DataSource.
- **Pooler config**: dev is inline in `.cloud/docker/docker-compose.yaml`; prod uses
  `deployment/config/pgbouncer.ini` with `auth_query` (multi-role) + TLS. The prod `generate-secrets` job
  (`deployment/scripts/generate-secrets.sh`) writes pgbouncer's `userlist.txt`, the `pgbouncer_auth` password and
  its certificate (SAN includes `pgbouncer`) into the secrets volume on first start; nothing is kept in sync by hand.
- **Roles**: each client connects as its own least-privilege role. Prod: the API `cc_api`, the package
  follower `cc_follower`, the other Go services `cc_service`, the plugins `cc_plugin`, the knowledge service
  `cc_knowledge` and the exporters `cc_exporter`; dev runs everything as `postgres` except the follower,
  which is `cc_follower` there too. `cc_follower` alone may write knowledge `package` and `version` (the
  metadata licence and outdated results come from) and may update only an analysis's `status` and `config`.
  The init script creates the roles; the migrate job applies `cc_follower`'s table grants on every run,
  creates the role on an install that predates it (from `PG_FOLLOWER_PASSWORD`, sent as a SCRAM secret),
  and fails rather than skip them. pgbouncer needs no change per role: prod looks each one up with
  `auth_query`, dev through its `postgres` `auth_user`.
- **Budget**: dev keeps `default_pool_size(20) × (roles × databases)` under `max_connections` 300 (two roles,
  `postgres` and `cc_follower`: 160). Prod caps
  pgbouncer at `max_db_connections(20) × 4 databases = 80` server connections, under `max_connections`
  (`PG_MAX_CONNECTIONS`, default 100), whatever the replica count.
- **Replicas**: prod runs one replica of every service and plugin, sized for the reference machine (ADR 0012).
  For more, see "Larger instances" in `deployment/README.md` (downloader×8, each analysis plugin×4).
- **Memory**: prod's default containers' memory limits add up to at most 6.5 GiB (the reference machine's 8 GiB minus
  1.5 GiB for the OS); `.cloud/scripts/measure/memory-budget.sh` checks it with GOMEMLIMIT and `rabbitmq.conf`.
