FROM mcr.microsoft.com/devcontainers/base:debian-12

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      make \
      curl \
      ca-certificates \
      jq \
 && rm -rf /var/lib/apt/lists/*
