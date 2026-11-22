# API fuzz

Nightly Schemathesis run against a real instance's OpenAPI description (`/api/api_doc-json`). It fails on a 5xx (`not_a_server_error`) or a response that breaks the schema (`response_schema_conformance`). The workflow is `.github/workflows/api-fuzz.yml`: it builds the trimmed real stack at the submodule pointers, runs `api-fuzz.sh run` once per auth provider, and a separate `report` job opens, comments on or closes the provider's `ci-failure` issue (`API fuzz failing as <provider>`).

## Files

- `api-fuzz.sh`: `run`, `issue-body` and `report`; `api-fuzz.sh` with no arguments prints the usage.
- `schemathesis-image.txt`: the image, pinned by version and digest. To bump it, pick a release at least two weeks old and take the digest of its multi-arch index from the registry.
- `excluded-operations.txt`: operationIds the run never calls, because they would delete the account or end its sessions.

## Auth providers

`--auth NAME` calls the function `auth_<name>` (dashes become underscores) in `api-fuzz.sh`, which prints the header sent on every request.

- `dev-account`: logs in through `POST /auth/authenticate` (`LOGIN_EMAIL` and `LOGIN_PASSWORD`, default the dev account).
- `token`: sends `API_TOKEN` as a bearer token, for an Organization token.

To add a provider, write its function, then add its name to the `auth` matrix of both jobs in the workflow.

## Replaying a failure

The issue lists each failing operation with the request to replay as `curl`. Schemathesis shows the token and any value that looks secret as `[Filtered]`. To rerun the same generated cases, on a machine with Docker and a running stack:

```sh
API_URL=https://localhost/api CURL_CA=<Caddy root certificate> bash scripts/api-fuzz/api-fuzz.sh run --auth dev-account --out /tmp/fuzz --seed <seed from the issue> -- --include-method GET
```

Arguments after `--` go to `schemathesis run` as they are; `--include-method GET` keeps a run on a stack you use read-only. `stack.sh ca FILE` writes the certificate of the CI stack; a dev stack's API also answers on `http://localhost:3000`.

Once a case is fixed, commit it as a test in `api/test/integration/api-fuzz-regressions.integration.e2e-spec.ts`.
