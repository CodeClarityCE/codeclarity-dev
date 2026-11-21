# Keep the submodules, and test same-named branches across them together

Before beta we weighed merging the api, frontend, deployment and backend repos (and the backend's own nested repos) into one monorepo, since a change that spans repos means several PRs and pointer bumps. We keep the submodules, each repo with its own CI, releases and history. To make a cross-repo change testable as one unit, a contributor uses the same branch name in every repo they touch, and umbrella CI checks out that branch in each submodule that has it (`develop` otherwise) before running the real-stack journeys and the results gate.

## Considered Options

- One monorepo with per-image releases by path filter: simplest for contributors, but it rewrites every repo's history, CI and release script, and would break every existing clone.
- Flatten only the backend's nested repos into `backend`: removes one level of nesting, but still means moving every plugin's history and release.

## Consequences

- The branch name is the link between PRs in different repos; `CONTRIBUTING.md` documents the flow with an example.
- `scripts/release-all.sh` stays the way releases are ordered across repos.
