<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/CodeClarityCE/identity/blob/main/logo/vectorized/logo_name_white.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/CodeClarityCE/identity/blob/main/logo/vectorized/logo_name_black.svg">
  <img alt="codeclarity-logo" src="https://github.com/CodeClarityCE/identity/blob/main/logo/vectorized/logo_name_black.svg">
</picture>
<br>
<br>

Secure your software empower your team.

[![License](https://img.shields.io/github/license/codeclarityce/codeclarity-dev)](LICENSE.txt)

<details open="open">
<summary>Table of Contents</summary>

- [Overview](#overview)
- [License](#license)
- [Requirements](#requirements)
- [Setup Instructions](#setup-instructions)
  - [1. Download and Execute the Setup Script](#1-download-and-execute-the-setup-script)
  - [2. Update DB (Optional)](#2-update-db-optional)
  - [3. Make Commands](#3-make-commands)
- [Start using the platform](#start-using-the-platform)
- [Contributing](#contributing)
- [Reporting Issues](#reporting-issues)

</details>

---
<br>

![CodeClarity! Secure your software empower your team!](https://github.com/CodeClarityCE/identity/blob/main/illustration/rasterized/demo_illu.png)

## Overview

This repository contains all the necessary tools and dependencies to develop on CodeClarity. It includes Docker containers, build scripts, and configuration files required to set up your local development environment.

## License

This project is licensed under the AGPL-3.0-or-later license.  You can find the full license details in the [LICENSE](./LICENSE) file.

## Requirements

*   **curl:** Used for downloading the setup script and dumps.
*   **make:** Used for automating certain build and deployment tasks.
*   **golang >= 1.24** Used for plugins and downloadable [here](https://go.dev/dl/).
*   **Docker:**  A containerization platform.  [Installation instructions](https://docs.docker.com/engine/install/) are available on the Docker website.
*   **Docker Compose:** A tool for defining and running multi-container Docker applications. [Installation instructions](https://www.digitalocean.com/community/tutorials/how-to-install-and-use-docker-compose-on-ubuntu-20-04) can be found here.

## Setup Instructions

### 1. Download and Execute the Setup Script

This script automates the cloning of the development environment repository and initiates the setup process.
```bash
curl -O https://raw.githubusercontent.com/CodeClarityCE/codeclarity-dev/main/setup.sh && sh setup.sh
```

### 2. Update DB (Optional)

Please apply for an NVD API key [here](https://nvd.nist.gov/developers/request-an-api-key), and fill it in `codeclarity-dev/.cloud/env/.env.makefile`.

Run the command to update the knowledge DB:

```bash
make knowledge-update
```

Your development environment is now set up.

### 3. Make Commands
Once the initial configuration is complete, you no longer need to execute the setup script to start the platform. 
Use ```make``` to list all the possible actions:

```bash
# —— 🦉 CodeClarity's Makefile 🦉 —————————————————————————————————— 
help                           Outputs this help screen
# —— Commands for the dev env 💻 ——————————————————————————————————————————————————————————————— 
build                          Builds the Docker images
up                             Starts the Docker images
down                           Stops the Docker images
pull                           Pulls the Docker images
logs                           Displays the logs of the Docker images
# —— Commands to test production 🎯 ——————————————————————————————————————————————————————————————— 
build-prod                     Builds de production Docker images
up-prod                        Starts the Docker images in prod mode
down-prod                      Stops the Docker images in prod mode
# —— Commands to setup database 💾 ——————————————————————————————————————————————————————————————— 
knowledge-setup                Creates the database
knowledge-update               Updates the database
# —— Commands to dump and restore database 💾 ——————————————————————————————————————————————————————————————— 
download-dumps                 Downloads the database dump
dump-database                  Dumps the database
restore-database               Restores the database
```

## Start using the platform

You can visit [https://localhost:443](https://localhost:443) to start using the platform. You might need to accept the self-signed certificate generated by Caddy.

If you imported the dump we provide, you can connect using the following credentials:

- login: `john.doe@codeclarity.io`
- password: `ThisIs4Str0ngP4ssW0rd?`

Now, follow [this guide](https://doc.codeclarity.io/docs/0.0.0/create-analysis) to create your first analysis!

## Contributing

If you'd like to contribute code or documentation, please see [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines on how to do so.

## Reporting Issues

Please report any issues with the setup process or other problems encountered while using this repository by opening a new issue in this project's GitHub page.
