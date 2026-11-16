# Setup is Compose jobs, and production installs from a released Compose file

Setting up CodeClarity was spread over three scripts (dev `setup.sh`, the broker's `seed`, `deployment/setup.sh`) that had drifted apart, prompted on the terminal and needed Go, Node, pnpm and git-lfs on the host. Every setup step is now an idempotent one-shot job in the Compose stack, living in the image that already has its tools, and dev and production run the same jobs. A developer runs `make up` on a fresh clone; an operator downloads a versioned Compose file and `.env.example` from a `deployment` release, sets the version and domain, and runs `docker compose up -d` for both install and upgrade. There is no installer script, and the knowledge dump ships as a CI-built image instead of a Git LFS file.

## Considered Options

- Improved shell installer: keeps the drift between three copies and the host-tool dependencies that broke setup.
- A released Go CLI (`codeclarity install|upgrade|create-user`): tidy, but one more signed binary per OS and architecture, and operators would still need Docker underneath.
- Ansible: built for fleets, adds Python on the operator side for a single-host target.
- Compose application published as an OCI artifact (`docker compose -f oci://…`): rejects bind mounts, and operators cannot read or edit the file as easily as a downloaded one.
- Knowledge dump in Git LFS (the previous design): needs git-lfs, spends the org's LFS bandwidth on every clone, and is versioned apart from releases.
- Migrations on API start (the previous design): replicas race, and dev ran them a third way through host `ts-node`.

## Consequences

- Setup never prompts. A job that finds its work already done does nothing, so running `up` again is always safe; wiping data is only `make reset` with an explicit flag.
- Production restores only the knowledge dump. The app database starts empty from migrations, and the first user comes from a `create-user` command, so no instance ships with a known login.
- Secrets are generated on first start and never overwritten; no real secret files live in Git.
- The knowledge-dump image is built, gated and attested by a scheduled CI workflow, and old tags are pruned except those a release pins.
- Offline installs are no longer supported.
