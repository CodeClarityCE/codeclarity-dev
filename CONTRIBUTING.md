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
  - [Development Setup](#development-setup)
  - [Pull Request Process](#pull-request-process)
  - [AGPL License Requirements](#agpl-license-requirements)
  - [Reporting Issues](#reporting-issues)
  - [Community \& Support](#community--support)

</details>

---

<br>

### How to Contribute

- Fork the repository and create your branch from `main`.
- Make your changes, following our code style and best practices.
- Add or update tests as needed.
- Ensure your code builds and passes all tests.
- Submit a pull request with a clear description of your changes.

### Code of Conduct

Be respectful and inclusive. Harassment or discrimination of any kind will not be tolerated.

### Development Setup

- Setup instruction can be found in the [README](./README.md).
- Run `make hooks` once after cloning. It points the git hooks of this repo and every submodule at `.githooks/`, whose pre-commit scans your staged changes for secrets with gitleaks. It needs either the `gitleaks` binary on your PATH (the devcontainer has it) or Docker, which runs the same pinned image as CI. With neither, the commit is refused; `git commit --no-verify` skips the scan, but CI still runs it on your PR.
- Tests that need a token-shaped value should use one like `glpat-test-token`, or build it at run time (a prefix joined to repeated characters), since `glpat-` followed by 20 x's is flagged by the scan and rejected by GitHub push protection.
- If the scan flags a dev key or test fixture on purpose, add its fingerprint (printed by the scan) to that repo's `.gitleaksignore`, under a `#` line saying why. If it might be a real secret, rotate it and tell the maintainers instead.
- Ensure you can build and run the project locally before submitting changes.

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
