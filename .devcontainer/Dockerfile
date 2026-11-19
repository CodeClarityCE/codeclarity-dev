FROM mcr.microsoft.com/devcontainers/base:debian-13@sha256:2e826a6ae92e5744cc0a471a03b4411e64f6b7cc6af3adaecddad697f0018f10

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      make \
      curl \
      ca-certificates \
      jq \
      # Headless browser for debugging the frontend with Playwright. Taken
      # from the signed Debian archive (security updates via apt) rather than
      # Playwright's own CDN download; Playwright drives it through
      # PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH (see devcontainer.json).
      chromium \
      fonts-liberation \
 && rm -rf /var/lib/apt/lists/*

# gitleaks for the pre-commit secret scan (.githooks/), which has no docker CLI here. Same release
# as .githooks/gitleaks.env; each download is checked against the release's sha256.
ARG GITLEAKS_VERSION=8.30.1
RUN set -eu; \
    case "$(dpkg --print-architecture)" in \
      amd64) arch=x64; sum=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb ;; \
      arm64) arch=arm64; sum=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080 ;; \
      *) echo "no gitleaks checksum for $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac; \
    tarball="gitleaks_${GITLEAKS_VERSION}_linux_${arch}.tar.gz"; \
    curl -fsSL -o "/tmp/$tarball" "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/$tarball"; \
    echo "$sum  /tmp/$tarball" | sha256sum -c -; \
    tar -xzf "/tmp/$tarball" -C /usr/local/bin gitleaks; \
    rm "/tmp/$tarball"; \
    gitleaks version

# Mount points for the container-only node_modules and pnpm store volumes (docker-compose.yml),
# owned by vscode so each new volume starts writable for that user.
RUN install -d -o vscode -g vscode \
      /home/vscode/.local /home/vscode/.local/share /home/vscode/.local/share/pnpm \
      /workspaces/codeclarity-dev/node_modules \
      /workspaces/codeclarity-dev/api/node_modules \
      /workspaces/codeclarity-dev/frontend/node_modules
