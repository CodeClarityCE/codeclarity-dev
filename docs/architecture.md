# Architecture overview

How CodeClarity is put together, and how a request in the web app becomes an analysis. It is written for people
reading the code for the first time; the agent docs in [`docs/agents/`](agents/) and the decisions in
[`docs/adr/`](adr/) go deeper. Terms in **bold** are defined in [`GLOSSARY.md`](../GLOSSARY.md).

## The parts

```text
 browser
    |
  Caddy  (TLS, serves the web app, forwards /api)
    |            \
 frontend        API  (NestJS)
 (Vue app)        |  \
                  |   RabbitMQ  <------------------------------+
                  |      |                                     |
                  |   dispatcher --> downloader --> dispatcher |
                  |      |                                     |
                  |      +--> plugins (one queue each) --------+
                  |
              pgbouncer --> PostgreSQL: codeclarity, knowledge, config, plugins
                  ^
     services and plugins reach Postgres the same way
```

- **Frontend** (`frontend/`, Vue 3 and TypeScript): the web app. It talks only to the API.
- **API** (`api/`, NestJS and TypeORM): users, organizations, projects, **analyzers** and results. It owns the
  schema of all four databases through its migrations, and it is the only part the outside world calls.
- **Services** (`backend/services/`, Go):
  - `dispatcher` drives every analysis from start to end, stage by stage, and recovers analyses whose messages were
    lost in a restart ([restart-recovery.md](restart-recovery.md)).
  - `downloader` clones the project's repository at the requested ref, when the analysis needs the source.
  - `knowledge` keeps the knowledge database current from its **knowledge sources** (NVD, GCVE, OSV, KEV and others).
  - `packageFollower` fetches package metadata from registries such as npm and Packagist for the packages an SBOM
    names.
  - `scheduler` starts scheduled analyses; `notifier` sends notifications.
- **Plugins** (`backend/plugins/`, Go): each one does one stage of an analysis, such as building the SBOM of an npm
  or PHP project, finding vulnerabilities, finding licences, or running CodeQL. An **analyzer** is an ordered set of
  plugin stages; the Default Analyzer is the one every instance starts with.
- **Utilities** (`backend/utilities/`, Go): libraries shared by services and plugins (database and RabbitMQ helpers,
  shared types, semver parsing, the plugin boilerplate).
- **PostgreSQL**, behind pgbouncer: `codeclarity` (app data and results), `knowledge` (vulnerability and package
  data), `config` (the source watermarks of the knowledge update) and `plugins` (what each plugin needs and
  produces). Pool sizes: [database-pooling.md](database-pooling.md).
- **RabbitMQ**: the queues between the API, the dispatcher, the downloader and the plugins.

Every part is its own repository, checked out here as a submodule; see
[CONTRIBUTING.md](../CONTRIBUTING.md#repositories-and-submodules).

## From a request to an analysis

1. A user starts an **analysis** of a project with an analyzer in the web app. The API checks the analyzer's plugins
   are available, records the analysis in `codeclarity` and sends a message on the `api_request` queue. From then
   on the analysis is submitted, even if nothing has picked it up yet.
2. The `dispatcher` reads the analyzer's stages. If the first stage needs the source, it asks the `downloader`,
   which clones the repository and answers on `downloader_dispatcher`.
3. For each stage, the dispatcher sends a message to the queue of each plugin in it (`dispatcher_<plugin>`). A plugin
   reads its inputs from the database (for example the SBOM an earlier stage wrote), does its work, writes its
   result to `codeclarity` and answers on `plugins_dispatcher`.
4. When every plugin of a stage has answered, the dispatcher starts the next stage. After the last one it marks the
   analysis finished, or failed with the reason a plugin gave.
5. The web app shows the results by asking the API, which reads them from `codeclarity` and joins them with
   `knowledge`.

The queues hold no state the system cannot rebuild: the analysis rows in Postgres do, so the dispatcher's reaper can
start a lost analysis again after a crash or restart.

## Running it

- Development: `make up` in this repository starts every part with hot reload; see the [README](../README.md).
- Production: one Compose file, released from [`deployment/`](../deployment/), sized for the **reference machine**
  (ADR 0012); its README has the support matrix.
- Optional components, such as CodeQL and monitoring, are off until an operator turns on their Compose profile.
