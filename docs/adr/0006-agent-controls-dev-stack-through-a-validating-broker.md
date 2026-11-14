# The agent runs its dev stack on a private Docker daemon behind a validating broker

The AI agent in the devcontainer must run `make up`, `make down` and full automated tests by itself, without ever gaining root on the host. It gets its own Docker daemon in a privileged sidecar, and reaches it only through a broker sidecar that exposes fixed commands and validates the resolved Compose config against an allowlist before running it. The host Docker socket is not mounted anywhere, and the agent's stack is separate from the developer's.

## Considered Options

- Docker-in-Docker inside the devcontainer: needs `--privileged` on the container the agent runs in, which removes the sandbox.
- Mounting the host Docker socket: root-equivalent on the Docker Desktop VM, and `:ro` does not restrict the API.
- Filtering socket proxy: `up` needs container create, so safety depends on inspecting every create request.
- Broker on the host socket: lighter, but the agent's `make down` would stop the developer's stack.
- Dedicated Colima or Lima VM: strongest isolation, but needs setup on the Mac outside the repo.

## Consequences

- The agent can edit Compose files, so limiting commands is not enough. The broker runs only the exact resolved config it validated.
- Docker follows symlinks in bind sources when it mounts them. The daemon therefore sees only an exact list of repo paths, each its own mount point, and the validator accepts only those. A new bind mount needs a change to `.devcontainer/docker-compose.yml` and `policy.go`, then a rebuild.
- The `alloy` service needs the inner Docker socket, so it is pinned to a fixed image, command and mounts, with no environment.
- The broker's code and policy are baked into its image, so agent edits only take effect when a developer rebuilds. Review `.devcontainer/` changes before rebuilding.
- The broker shares the daemon's network, because BuildKit fetches registry tokens through the client and builds fail without it. It therefore has outbound network access while holding the Docker socket, and it listens only on its Unix socket.
- The inner daemon is privileged, so a validator bug could reach the Docker Desktop VM. The validator is the component that has to be right.
