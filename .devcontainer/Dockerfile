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
