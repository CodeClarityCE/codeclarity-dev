# CI runs on GitHub Actions through central reusable workflows

Status: accepted

CI for every CodeClarityCE repo moves from a self-hosted Jenkins agent to GitHub-hosted runners. The pipeline logic lives once, in three reusable workflows in `CodeClarityCE/.github` (Go libraries, Go images, Node images), and each repo keeps a short caller that picks one and passes a few inputs. This replaces up to 25 near-identical Jenkinsfiles and the agent they needed, and keeps the existing posture: pinned toolchains, release secrets away from PR builds, and immutable releases.

## Considered Options

### Our own workflows by a moving `v1` tag, third-party actions by SHA

Callers reference the central workflows at `v1`, which moves with each non-breaking change; a breaking change goes out as `v2`. Every third-party action is pinned to a commit SHA and bumped by Dependabot.

- Pin our own workflows by SHA too: a central fix would need a PR in every repo, which is the duplication we are removing. We control `CodeClarityCE/.github`, so a moving tag there carries no outside supply-chain risk.
- Reference third-party actions by tag, as the old workflows did: a tag can be moved to different code, which is how the 2025 `tj-actions` compromise spread.

### Native arm64 runners instead of QEMU

Main builds run amd64 on `ubuntu-24.04` and arm64 on `ubuntu-24.04-arm`, each pushing by digest, and a merge job creates one manifest list.

- Keep building both architectures on one runner under QEMU: arm64 Go and Node builds run emulated and spend most of a release's time there.
- Cross-compile Go in the Dockerfiles: needs Dockerfile changes and does not help the Node images. Native arm64 runners are free for public repos, so neither is needed.

### The same pinned Go image and Dockerfile toolchain target instead of setup actions

Go jobs run in a job container from the same digest-pinned `golang:1.27.4` image Jenkins uses. Node jobs build the Dockerfile's `toolchain` target and run each step in it, so Node, corepack and pnpm versions still come from one place.

- `actions/setup-go` and `actions/setup-node`: they install a toolchain chosen by version string, not digest, so CI could drift from what the Dockerfiles build with, and pnpm would need a second source of truth next to `packageManager`.

### Keep the version-file release model instead of release-please

The version file (`config.json` or `package.json`) stays the source of truth: a PR to `main` must bump it, and a push to `main` builds, pushes the image and creates the tag and release only if the tag does not exist.

- release-please: it opens its own release PRs and bumps versions from commit messages per repo. Our releases cascade across repos through `go.mod` bumps driven by `scripts/release-all.sh`, which edits the version files and waits on each release in order. release-please would race the script on the same files and tags.

### One `ci` gate job as the contract

Every workflow ends in a job named `ci` that needs every other job and fails if any failed or was cancelled; skipped jobs count as success. The org ruleset requires `ci` on `main` in every repo, and the release script waits on `ci` by default.

- Require each job by name: job names differ per workflow and change over time, so the ruleset would need per-repo lists that break on every rename.
- No required check, as under Jenkins: nothing stops a merge to `main` with failing checks.

## Consequences

- The `ci` name is shared by the workflows, the org ruleset and `scripts/release-all.sh`. Renaming it means changing all three together, or merges and releases stall.
- A fix to the central workflows reaches every repo on the next run, so the central repo tests its own workflows against small fixtures before `v1` moves.
- The Go image digest lives once in the central repo. The "keep in sync with the Dockerfiles and `go.mod`" rule now points there instead of at the Jenkins helpers.
- Release jobs run only in a `release` environment limited to `main`, which alone holds the Docker Hub token, and only when the repo variable `CI_RELEASE` is `true`. Until a repo's first release through Actions is tested, Jenkins stays its releaser.
- The Jenkins agent requirements (Docker with buildx and QEMU, Pipeline Utility Steps, an authenticated `gh`, a `dockerhub` credential, the `inToolchain()` and `inGo()` helpers) are superseded once a repo switches. ADR 0006 governs the devcontainer agent's dev stack, not CI, and stays in force; only the Jenkins toolchain statements next to it in `CLAUDE.md` are superseded.
