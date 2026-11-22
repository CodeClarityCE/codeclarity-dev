<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/CodeClarityCE/identity/blob/main/logo/vectorized/logo_name_white.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/CodeClarityCE/identity/blob/main/logo/vectorized/logo_name_black.svg">
  <img alt="codeclarity-logo" src="https://github.com/CodeClarityCE/identity/blob/main/logo/vectorized/logo_name_black.svg">
</picture>

# CodeClarity Development Guide

**Secure your software, empower your team.**

[![License](https://img.shields.io/github/license/codeclarityce/codeclarity-dev)](LICENSE.txt)
[![Website](https://img.shields.io/badge/Website-Visit-blue)](https://www.codeclarity.io)

## 👋 Welcome Developers

This repository contains the complete CodeClarity development environment. Whether you're contributing to the core platform, developing plugins, or customizing CodeClarity for your organization, this guide will get you up and running quickly.

## 🚀 What is CodeClarity?

CodeClarity is a **powerful, open-source security analysis platform** that serves as an alternative to Snyk, Checkmarx, and Black Duck. It provides:

- **⚡ Fast source code analysis** - Identify dependencies, licenses, and vulnerabilities instantly
- **🏠 Full on-premises control** - Your code never leaves your environment
- **🔗 CI/CD integration** - Seamlessly integrates with GitHub Actions, Jenkins, and more
- **🧩 Extensible plugin system** - Create custom analysis pipelines with modular plugins
- **📊 Comprehensive reporting** - SBOM generation, vulnerability detection, license compliance

### Development Architecture

CodeClarity consists of several components:

- **Frontend** (Vue.js + TypeScript) - Modern web interface
- **API** (NestJS + TypeScript) - RESTful API server
- **Backend** (Go) - Core analysis engine and plugin system
- **Database** (PostgreSQL) - Data persistence layer
- **Message Queue** (RabbitMQ) - Asynchronous task processing

![CodeClarity Platform Overview](https://github.com/CodeClarityCE/identity/blob/main/illustration/rasterized/demo_illu.png)

<details open="open">
<summary>Table of Contents</summary>

- [CodeClarity Development Guide](#codeclarity-development-guide)
  - [👋 Welcome Developers](#-welcome-developers)
  - [🚀 What is CodeClarity?](#-what-is-codeclarity)
    - [Development Architecture](#development-architecture)
  - [📋 Prerequisites](#-prerequisites)
  - [⚡ Quick Start Guide](#-quick-start-guide)
  - [🛠️ Detailed Setup Instructions](#️-detailed-setup-instructions)
    - [1. Update the Knowledge Database (Optional)](#1-update-the-knowledge-database-optional)
    - [2. Available Make Commands](#2-available-make-commands)
      - [🔧 Development Commands](#-development-commands)
      - [🎯 Production Testing Commands](#-production-testing-commands)
      - [💾 Knowledge Database Commands](#-knowledge-database-commands)
  - [🎯 Development Workflow](#-development-workflow)
    - [Daily Development Routine](#daily-development-routine)
    - [Component Development](#component-development)
      - [Frontend Development (Vue.js + TypeScript)](#frontend-development-vuejs--typescript)
      - [API Development (NestJS + TypeScript)](#api-development-nestjs--typescript)
      - [Backend Development (Go)](#backend-development-go)
    - [Plugin Development](#plugin-development)
  - [🚀 Start Using the Platform](#-start-using-the-platform)
    - [Default Development Credentials](#default-development-credentials)
    - [Next Steps](#next-steps)
  - [🤝 Contributing](#-contributing)
    - [Development Guidelines](#development-guidelines)
  - [🐛 Reporting Issues](#-reporting-issues)
  - [📄 License](#-license)
    - [What This Means for Contributors](#what-this-means-for-contributors)

</details>

## 📋 Prerequisites

You need only two tools on your machine:

- **git** - [Install instructions](https://git-scm.com/downloads)
- **Docker** with the Compose plugin - [Docker Desktop](https://docs.docker.com/get-started/get-docker/) on macOS and Windows (WSL2), or [Docker Engine](https://docs.docker.com/engine/install/) on Linux

Go, Node, pnpm and Postgres all run inside the containers. The `make` commands below need `make`, which macOS (Xcode command line tools) and most Linux distributions already have.

> [!NOTE]
> **System Requirements:**
>
> - Minimum 8GB RAM (16GB recommended for full development)
> - At least 10GB free disk space
> - macOS, Linux, or Windows with WSL2 (run the commands inside your WSL2 distribution)

## ⚡ Quick Start Guide

```bash
git clone --recursive https://github.com/CodeClarityCE/codeclarity-dev.git
cd codeclarity-dev
make up
```

That is the whole setup. The first `make up` builds the images and runs the setup jobs before the app starts:

1. Creates the databases and their roles
2. Restores the knowledge database (vulnerability data) from the knowledge dump image, when it is empty
3. Runs the migrations of every database
4. Creates the `_test` databases for the API tests, the default developer account and the global default analyzer

Every job finds its work done on later runs, so `make up` is always safe to run again and never asks a question. If a job fails, the app services stay stopped and `make logs SERVICE=<job>` shows why.

Once it is up, visit [https://localhost:443](https://localhost:443) and log in with the [default development credentials](#default-development-credentials).

## 🛠️ Detailed Setup Instructions

### 1. Update the Knowledge Database (Optional)

The restored knowledge database is a recent snapshot of every knowledge source, so analyses work as soon as `make up` is done. To bring it up to date, start with the OSV advisories, which need no key and no account:

```bash
make knowledge-update-osv
```

A full update of every source (`make knowledge-update`) needs an NVD API key and takes hours; you only need it when you work on the knowledge sources:

1. **Get an NVD API Key**: Apply for a free API key from the [National Vulnerability Database](https://nvd.nist.gov/developers/request-an-api-key)

2. **Configure the API Key**: Copy `.cloud/env/.env.secrets.example` to `.cloud/env/.env.secrets` (gitignored) and set your key:

   ```bash
   NVD_API_KEY=your-api-key-here
   ```

3. **Update the Knowledge Database**:

   ```bash
   make knowledge-update
   ```

> [!NOTE]
> Both updates run inside the running stack, so they need `make up` first and nothing beyond git and Docker on your machine. See [docs/knowledge-dump.md](docs/knowledge-dump.md).

### 2. Available Make Commands

```bash
make help  # Show all available commands
```

#### 🔧 Development Commands

```bash
make up                       # Set up and start the development environment (SERVICE=name for one service)
make down                     # Stop the development environment, keeping its data
make build                    # Build the Docker images
make pull                     # Pull the latest Docker images
make logs                     # View container logs
make migrate                  # Apply new migrations (make migrate-<db> for one database)
make reset CONFIRM=reset      # Delete all data of the dev stack, then set it up again
```

`make reset` refuses to run without `CONFIRM=reset` on the command line.

#### 🎯 Production Testing Commands

```bash
make build-prod               # Build production Docker images
make up-prod                  # Start in production mode
make down-prod                # Stop production environment
```

#### 💾 Knowledge Database Commands

```bash
make knowledge-update-osv     # Update only the OSV advisories (no key needed; the first update to run)
make knowledge-update         # Update every source (needs an NVD API key)
make dump-knowledge           # Dump knowledge + config with a manifest, after the completeness gate
```

## 🎯 Development Workflow

### Daily Development Routine

1. **Start Your Environment**:

   ```bash
   make up
   ```

2. **View Logs** (in a separate terminal):

   ```bash
   make logs
   ```

3. **Make Your Changes** - Edit code in your preferred IDE

4. **Test Your Changes** - Changes are automatically reflected due to volume mounting

5. **Stop Environment** when done:

   ```bash
   make down
   ```

### Component Development

#### Frontend Development (Vue.js + TypeScript)

- **Location**: `frontend/` directory
- **Hot Reload**: Enabled in containers using `vite`
- **Access**: [https://localhost:443](https://localhost:443)
- **Build**: `make build` (rebuilds frontend container)

#### API Development (NestJS + TypeScript)

- **Location**: `api/` directory
- **Hot Reload**: Enabled in containers with `nest --watch`
- **Access**: API available at [https://localhost:443/api](https://localhost:443/api)
- **Documentation**: Swagger UI available in development mode

#### Backend Development (Go)

- **Location**: `backend/` directory
- **Hot Reload**: Enabled in containers with `Air`
- **Build**: `make build` (rebuilds backend services)
- **Plugins**: Located in `backend/plugins/` directory

### Plugin Development

CodeClarity's plugin system allows you to create custom analysis tools:

1. **Create Plugin Structure**:

   ```bash
   mkdir backend/plugins/my-plugin
   cd backend/plugins/my-plugin
   ```

2. **Implement Plugin Interface** - Follow existing plugin examples (Documentation coming soon)

3. **Register Plugin** - Add to plugin registry

4. **Test Plugin** - Use the platform's plugin testing framework

## 🚀 Start Using the Platform

Your development environment is ready! Access CodeClarity at [https://localhost:443](https://localhost:443).

> [!WARNING]
> You may need to accept the self-signed certificate generated by Caddy.

### Default Development Credentials

`make up` creates this account in the development stack only:

- **Username**: `john.doe@codeclarity.io`
- **Password**: `ThisIs4Str0ngP4ssW0rd?`

> [!IMPORTANT]
> A production instance has no pre-existing account; its operator creates the first user.

### Next Steps

1. **Explore the Platform** - Familiarize yourself with the UI and features
2. **Create Your First Analysis** - Follow the [analysis guide](https://doc.codeclarity.io/docs/0.0.21/tutorials/basic/create-analysis)
3. **Review the Architecture** - Read the [architecture overview](./docs/architecture.md)
4. **Start Contributing** - Check out our [contribution guidelines](./CONTRIBUTING.md)

## 🤝 Contributing

We welcome contributions from developers of all skill levels! Here's how to get started:

1. **Fork the Repository** - Create your own copy of the repository you change (most code lives in a submodule, such as `api` or `frontend`)
2. **Create a Feature Branch from `develop`** - `git switch develop && git switch -c feature/your-feature-name`; PRs go into `develop`
3. **Make Your Changes** - Follow our coding standards
4. **Test Thoroughly** - Ensure your changes don't break existing functionality
5. **Submit a Pull Request** - Describe your changes and their impact

For detailed guidelines, see [CONTRIBUTING.md](./CONTRIBUTING.md).

### Development Guidelines

- **Code Style**: Follow language-specific conventions (ESLint for TypeScript, gofmt for Go)
- **Testing**: Write tests for new features and bug fixes
- **Documentation**: Update relevant documentation
- **Commit Messages**: Use clear, descriptive commit messages

## 🐛 Reporting Issues

Found a bug or have a feature request? We'd love to hear from you!

1. **Check Existing Issues** - Avoid duplicates by searching first
2. **Use Issue Templates** - Helps us understand and resolve faster
3. **Provide Details** - Include environment info, steps to reproduce, and expected behavior
4. **Be Responsive** - Engage with maintainers if they need clarification

[Open an Issue →](https://github.com/CodeClarityCE/codeclarity-dev/issues/new)

## 📄 License

This project is licensed under the **AGPL-3.0-or-later** license. See the [LICENSE](./LICENSE) file for full details.

### What This Means for Contributors

- Your contributions will be under the same AGPL-3.0-or-later license
- You retain copyright to your contributions
- The project remains open source and free to use
- Commercial use is allowed under AGPL terms
