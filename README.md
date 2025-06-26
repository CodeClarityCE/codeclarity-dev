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
    - [1. Clone and Setup Development Environment](#1-clone-and-setup-development-environment)
    - [2. Configure Knowledge Database (Optional)](#2-configure-knowledge-database-optional)
    - [3. Available Make Commands](#3-available-make-commands)
      - [🔧 Development Commands](#-development-commands)
      - [🎯 Production Testing Commands](#-production-testing-commands)
      - [💾 Database Management Commands](#-database-management-commands)
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

Before setting up your development environment, ensure you have the following tools installed:

- **curl** - For downloading setup scripts and database dumps
- **make** - For automating build and deployment tasks
- **Go >= 1.24** - Required for backend plugins. [Download here](https://go.dev/dl/)
- **Docker** - Containerization platform. [Installation guide](https://docs.docker.com/engine/install/)
- **Docker Compose** - Multi-container orchestration. [Installation guide](https://docs.docker.com/compose/install/)

> [!TIP]
> **New to Docker?** Check out the [Docker Getting Started guide](https://docs.docker.com/get-started/) for a quick introduction.

> [!NOTE]
> **System Requirements:**
>
> - Minimum 8GB RAM (16GB recommended for full development)
> - At least 10GB free disk space
> - macOS, Linux, or Windows with WSL2

## ⚡ Quick Start Guide

**Want to start developing in 5 minutes?** Run this one-liner:

```bash
curl -O https://raw.githubusercontent.com/CodeClarityCE/codeclarity-dev/main/setup.sh && sh setup.sh
```

This will:

1. Clone the development repository
2. Set up all Docker containers
3. Initialize databases with sample data
4. Start the development environment

Once complete, visit [https://localhost:443](https://localhost:443) to access your local CodeClarity instance!

## 🛠️ Detailed Setup Instructions

### 1. Clone and Setup Development Environment

The setup script automates the entire development environment setup process:

```bash
curl -O https://raw.githubusercontent.com/CodeClarityCE/codeclarity-dev/main/setup.sh && sh setup.sh
```

**What this script does:**

1. **Environment Setup** - Clones the development repository and configures environment variables
2. **Container Orchestration** - Builds and starts all required Docker containers (frontend, API, backend, database, message queue)
3. **Database Initialization** - Downloads and restores sample data for immediate development
4. **Service Verification** - Ensures all services are running and properly connected

### 2. Configure Knowledge Database (Optional)

To work with the latest vulnerability data and enhance your development experience:

1. **Get an NVD API Key**: Apply for a free API key from the [National Vulnerability Database](https://nvd.nist.gov/developers/request-an-api-key)

2. **Configure the API Key**: Add your key to `codeclarity-dev/.cloud/env/.env.makefile`:

   ```bash
   NVD_API_KEY=your-api-key-here
   ```

3. **Update the Knowledge Database**:

   ```bash
   make knowledge-update
   ```

> [!NOTE]
> The knowledge database update can take 15-30 minutes depending on your internet connection. This step is optional for basic development but recommended for working with vulnerability detection features.

### 3. Available Make Commands

Once setup is complete, use these commands to manage your development environment:

```bash
make help  # Show all available commands
```

#### 🔧 Development Commands

```bash
make build                    # Build all Docker images
make up                       # Start development environment
make down                     # Stop development environment
make pull                     # Pull latest Docker images
make logs                     # View container logs
```

#### 🎯 Production Testing Commands

```bash
make build-prod               # Build production Docker images
make up-prod                  # Start in production mode
make down-prod                # Stop production environment
```

#### 💾 Database Management Commands

```bash
make knowledge-setup          # Initialize knowledge database
make knowledge-update         # Update vulnerability data
make download-dumps           # Download database dumps
make dump-database            # Create database backup
make restore-database         # Restore from backup
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

- **Username**: `john.doe@codeclarity.io`
- **Password**: `ThisIs4Str0ngP4ssW0rd?`

> [!IMPORTANT]
> These are development-only credentials. Change them for any production-like testing.

### Next Steps

1. **Explore the Platform** - Familiarize yourself with the UI and features
2. **Create Your First Analysis** - Follow the [analysis guide](https://doc.codeclarity.io/docs/0.0.21/tutorials/basic/create-analysis)
3. **Review the Architecture** - Understand how components interact
4. **Start Contributing** - Check out our [contribution guidelines](./CONTRIBUTING.md)

## 🤝 Contributing

We welcome contributions from developers of all skill levels! Here's how to get started:

1. **Fork the Repository** - Create your own copy of the project
2. **Create a Feature Branch** - `git checkout -b feature/your-feature-name`
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
