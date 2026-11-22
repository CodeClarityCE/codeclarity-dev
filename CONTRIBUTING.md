<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/CodeClarityCE/identity/blob/main/logo/vectorized/logo_name_white.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/CodeClarityCE/identity/blob/main/logo/vectorized/logo_name_black.svg">
  <img alt="codeclarity-logo" src="https://github.com/CodeClarityCE/identity/blob/main/logo/vectorized/logo_name_black.svg">
</picture>
<br>
<br>

Secure your software empower your team.

[![License](https://img.shields.io/github/license/codeclarityce/codeclarity-dev)](LICENSE.txt)
[![Website](https://img.shields.io/badge/Website-Visit-blue)](https://www.codeclarity.io)

CodeClarity is an open-source alternative to Snyk, Checkmarx, and Black Duck, offering fast source code analysis to identify dependencies, licenses, and vulnerabilities instantly.

It runs fully on-premises, giving you full control over your code.

Integrate CodeClarity into your CI/CD (e.g., GitHub Actions, Bash) to block vulnerable code automatically.

Create custom analysis pipelines by linking plugins. Currently, there are three in-house plugins (SBOM builder, vulnerability finder, license finder) and one external (CodeQL), with more coming soon.

<br>

![CodeClarity! Secure your software empower your team!](https://github.com/CodeClarityCE/identity/blob/main/illustration/rasterized/demo_illu.png)

<br>

## Contributing to CodeClarity

Thank you for your interest in contributing to CodeClarity! We welcome contributions from everyone. This document outlines how you can help and the rules you must follow.

<details open="open">
<summary>Table of Contents</summary>

- [Contributing to CodeClarity](#contributing-to-codeclarity)
  - [How to Contribute](#how-to-contribute)
  - [Code of Conduct](#code-of-conduct)
  - [Repositories and Submodules](#repositories-and-submodules)
  - [Development Setup](#development-setup)
  - [First Run Without an NVD Key](#first-run-without-an-nvd-key)
  - [Changes That Span Repositories](#changes-that-span-repositories)
  - [Pull Request Process](#pull-request-process)
  - [AGPL License Requirements](#agpl-license-requirements)
  - [Reporting Issues](#reporting-issues)
  - [Community \& Support](#community--support)

</details>

---

<br>

### How to Contribute

- Fork the repository and create your branch from `develop`. Every repository takes pull requests into `develop`; `main` only receives releases, so a PR opened against `main` will be retargeted.
- Make your changes, following our code style and best practices.
- Add or update tests as needed.
- Ensure your code builds and passes all tests.
- Submit a pull request with a clear description of your changes.

### Code of Conduct

Be respectful and inclusive. Harassment or discrimination of any kind will not be tolerated.

### Repositories and Submodules

This repository (`codeclarity-dev`, the umbrella) holds the dev stack, the docs, the ADRs and the cross-repo CI. The code lives in other repositories, checked out here as git submodules:

| Path                  | Repository                     | What it is                                                                     |
| --------------------- | ------------------------------ | ------------------------------------------------------------------------------ |
| `api`                 | `CodeClarityCE/api`            | NestJS API, and the migrations of every database                               |
| `frontend`            | `CodeClarityCE/frontend`       | Vue web app                                                                    |
| `deployment`          | `CodeClarityCE/deployment`     | Production Compose file and the operator guide                                 |
| `backend`             | `CodeClarityCE/backend`        | Holds the Go repositories below as its own submodules                          |
| `backend/services/*`  | `CodeClarityCE/service-<name>` | Dispatcher, downloader, knowledge and other services                           |
| `backend/plugins/*`   | `CodeClarityCE/plugin-<name>`  | Analysis plugins (SBOM builders, vulnerability finder, licence finder, CodeQL) |
| `backend/utilities/*` | `CodeClarityCE/utility-<name>` | Shared Go libraries                                                            |

Each submodule is a full repository with its own issues, CI, releases and history (`docs/adr/0020-keep-submodules-and-test-same-named-branches-together.md`). A few things follow from that:

- Clone with `git clone --recursive`, or run `git submodule update --init --recursive` in an existing clone.
- The umbrella records one commit of each submodule (its pointer). `git submodule update` checks out those commits, detached; run `git switch develop` (or your branch) inside a submodule before you commit there.
- Commit and push inside the submodule, then open the PR in that submodule's repository. The umbrella only changes when its own files change, or when maintainers move the pointers.
- A change to one area goes to that area's repository; work that spans repositories is tracked in `CodeClarityCE/codeclarity-dev`.
- How the parts fit together: [docs/architecture.md](./docs/architecture.md).

### Development Setup

- Setup instruction can be found in the [README](./README.md).
- Run `make hooks` once after cloning. It points the git hooks of this repo and every submodule at `.githooks/`, whose pre-commit scans your staged changes for secrets with gitleaks. It needs either the `gitleaks` binary on your PATH (the devcontainer has it) or Docker, which runs the same pinned image as CI. With neither, the commit is refused; `git commit --no-verify` skips the scan, but CI still runs it on your PR.
- Tests that need a token-shaped value should use one like `glpat-test-token`, or build it at run time (a prefix joined to repeated characters), since `glpat-` followed by 20 x's is flagged by the scan and rejected by GitHub push protection.
- If the scan flags a dev key or test fixture on purpose, add its fingerprint (printed by the scan) to that repo's `.gitleaksignore`, under a `#` line saying why. If it might be a real secret, rotate it and tell the maintainers instead.
- Ensure you can build and run the project locally before submitting changes.

### First Run Without an NVD Key

You do not need an NVD API key, or any account, to run the stack and an analysis:

```bash
git clone --recursive https://github.com/CodeClarityCE/codeclarity-dev.git
cd codeclarity-dev
make hooks
make up                    # restores the knowledge database from the knowledge dump image
make knowledge-update-osv  # brings the OSV advisories up to date, no key needed
```

Then log in at <https://localhost:443> with the dev account from the [README](./README.md#default-development-credentials) and run the Default Analyzer on a project. The restored dump already holds every knowledge source (NVD, GCVE, OSV, KEV and the rest), so results are complete up to the dump's date; `make knowledge-update-osv` adds the OSV advisories published since the dump was made. A full `make knowledge-update` (every source, a few hours) needs an NVD API key and is only worth it when you work on the knowledge sources themselves; see [docs/knowledge-dump.md](./docs/knowledge-dump.md).

### Changes That Span Repositories

When one change needs edits in more than one repository, use **the same branch name in every repository you touch**, and open a PR in each one, including one in this umbrella. Umbrella CI then tests them as one unit: on an umbrella PR it checks out your branch in each submodule that has a branch of that name, and `develop` in the others, before it builds the stack and runs the real-stack journeys and the results gate (`scripts/same-named-branches.sh`, ADR 0020). The branch name is the only link between the PRs.

Example: a new field shown in the UI needs an API change and a frontend change.

```bash
# In each submodule you change, branch from develop with the same name.
cd api && git switch develop && git pull && git switch -c feat/123-risk-score
# ...edit, test, commit...
git push -u origin feat/123-risk-score

cd ../frontend && git switch develop && git pull && git switch -c feat/123-risk-score
# ...edit, test, commit...
git push -u origin feat/123-risk-score

# In the umbrella, the same name again, from develop.
cd .. && git switch develop && git pull && git switch -c feat/123-risk-score
git add api frontend   # optional: point the submodules at your commits
git commit -m "Test the risk score across api and frontend"
git push -u origin feat/123-risk-score
```

Open three PRs into `develop`: `api`, `frontend` and `codeclarity-dev`, each from `feat/123-risk-score`, and link them to each other in their descriptions. The umbrella PR's `Check out the same-named branches in the submodules` step prints which commit each submodule was tested at:

```text
Submodule checkouts for the same-named-branch PR feat/123-risk-score:
backend                                  develop (fallback)                       9a0b1c2
backend/services/dispatcher              develop (fallback)                       3d4e5f6
...
api                                      PR branch feat/123-risk-score            1a2b3c4
frontend                                 PR branch feat/123-risk-score            5d6e7f8
deployment                               develop (fallback)                       7a8b9c0
```

Things to know:

- The umbrella PR needs a commit to exist. If you have no umbrella change, moving the pointers of the submodules you changed (`git add api frontend`) is a good one: it is what the umbrella will record once your PRs are merged.
- Branches are looked up on the CodeClarityCE repositories, not on forks. If you work from forks, say so in the umbrella PR and a maintainer will push your branches upstream so CI can find them.
- If no submodule has a branch of that name, CI tests the submodules at their pointers, as for any umbrella PR.
- Merge order is the dependency order: libraries in `backend/utilities` first, then the repositories that use them. `scripts/release-all.sh` releases them in that order.

### Pull Request Process

- Clearly describe the problem and solution in your PR.
- Reference related issues if applicable.
- If your contribution changes existing behavior, update the documentation.
- If the `results gate` check fails, your change moved what users see: a vulnerability, SBOM entry or licence of a fixture project appeared or disappeared, and the job log lists each one. If that is intended, download the failed job's `results-gate-run` artifact, run `sh scripts/results-gate/gate.sh update <that folder>` and commit `scripts/results-gate/expected/` in the same PR, so the reviewer sees the change in findings. See [scripts/results-gate/README.md](./scripts/results-gate/README.md).
- All code must be reviewed before merging.

### AGPL License Requirements

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).

By contributing, you agree that:

- All contributions will be licensed under AGPL-3.0[1].
- You must include prominent notices in your code stating:
  - That you have modified the code and the date of modification[1].
  - That your changes are released under AGPL-3.0[1].
- If your contribution includes interactive user interfaces, they must display appropriate legal notices as required by the AGPL[1].
- You grant a non-exclusive, worldwide, royalty-free patent license for your contributions as described in section 11 of the AGPL[1].

For more, see [LICENSE](./LICENSE).

### Reporting Issues

- Search existing issues before opening a new one.
- Provide detailed steps to reproduce the problem.
- Include logs, screenshots, or other helpful information.

### Community & Support

- [Join our Discord server](https://discord.gg/5m6qrxrVzc)

---

Thank you for helping make CodeClarity better!

---

**References:**

- [1] [AGPL-3.0 License Full Text](https://www.gnu.org/licenses/agpl-3.0.html)

---
