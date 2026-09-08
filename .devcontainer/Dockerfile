FROM mcr.microsoft.com/devcontainers/base:debian-12@sha256:23fa69fed758b7927c60061317d73baf7d66b9fca5c344e80bce3a940b229af0

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      make \
      curl \
      ca-certificates \
      jq \
 && rm -rf /var/lib/apt/lists/*
