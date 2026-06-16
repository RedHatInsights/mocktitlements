# mocktitlements

## Project Overview

`mocktitlements` is a Go HTTP server that mocks the Red Hat Hybrid Cloud Console Entitlements API
and Service Accounts API for local development and integration testing. It translates Keycloak admin
API data into the response shapes consumed by Console platform microservices. The service is
distributed as a container image and is intended to run alongside a local Keycloak instance via
Docker Compose.

## Dependencies

**Runtime:**
- Go 1.25
- Keycloak instance (admin API access required at startup)
- PostgreSQL (only required for Keycloak; not accessed directly)

**Key Go libraries:**
- `go.uber.org/zap` — structured logging
- `github.com/redhatinsights/platform-go-middlewares/identity` — `x-rh-identity` header parsing
- `golang.org/x/oauth2` — OAuth2/OIDC client credentials for Keycloak admin API
- `github.com/google/uuid` — UUID generation for service accounts

**E2E tests (Node.js, not part of the compiled artifact):**
- Node 24, Mocha, Chai, `openid-client`

All tool versions are pinned in `.tool-versions` (asdf).

## Development Commands

```sh
# Build
go build

# Unit tests
go test -v -race ./...

# Lint (47 linters, see .golangci.yml)
golangci-lint run

# Start the full stack (mocktitlements + Keycloak + PostgreSQL)
docker compose -f deployments/compose.yaml up -d --build

# Install E2E test dependencies
npm i --save-dev --prefix test

# Run E2E tests (requires running stack)
npm --prefix test test

# Rebuild mocktitlements only and re-run E2E (when Keycloak/Postgres are already up)
./rebuild_and_test.sh
```

CI runs `go test -v -race -coverprofile=coverage.out -covermode=atomic ./...` for unit tests and
the full Docker Compose stack for E2E tests. Linting runs `golangci-lint` with `--only-new-issues`
on pull requests.

See [Development Setup][readme-dev] in the README for the full command reference, including SELinux
notes and VSCode debug configuration.

## Architecture

Single-binary Go application (`main` package, entry point `main.go`). Core packages:

- `keycloak/` — Keycloak admin API client and `x-rh-identity` parsing
- `serviceaccounts/` — HTTP handler for the Service Accounts API subtree

The server uses `net/http` directly with no web framework. All state is stored in Keycloak; the
application is stateless. See [ARCHITECTURE.md][architecture] for design decisions, tradeoffs, and
detailed component analysis.

## Code Style

- Linter: `golangci-lint` (47 linters configured in `.golangci.yml`), enforced in CI
- Formatters (run via golangci-lint): `gofmt` with `simplify: true`, `goimports` with local prefix
  `github.com/RedHatInsights/mocktitlements`
- Language version: Go 1.25
- Import grouping: stdlib first, then external, then local (enforced by `goimports`)
- Test files have relaxed rules: `errcheck`, `goconst`, and `gocyclo` are excluded for `_test.go`
  paths

## Common Mistakes

1. **The E2E test stack must be running before tests execute.** `npm --prefix test test` will
   fail immediately if Keycloak is not reachable. Keycloak also needs time to finish importing the
   `redhat-external` realm after startup — the CI pipeline waits for this with
   `deployments/wait_for_keycloak_import.sh`.

2. **`KEYCLOAK_SERVER` must be set.** If the environment variable is empty, the OAuth2 token URL
   resolves to a relative path and all Keycloak calls fail at runtime with no descriptive error.
   There is no startup validation.

3. **User attributes must be complete.** `ParseUsers()` silently filters out any Keycloak user
   missing any of the required attributes (`is_active`, `is_org_admin`, `is_internal`, `account_id`,
   `org_id`, `account_number`, `entitlements`, `newEntitlements`). A user not appearing in
   entitlement responses is almost always caused by missing attributes, not a bug in the handler.

4. **Service account entitlements are copied at creation time.** Changing a user's `newEntitlements`
   after a service account is created does not update the service account's entitlements.

5. **The delete endpoint has a known URL routing bug.** The path rewrite in
   `deleteServiceAccount()` is applied to a local variable and has no effect on the actual outgoing
   request. Do not attempt to fix this without first reading the full context in `ARCHITECTURE.md`.

## Testing

Unit tests live in `main_test.go` and test `keycloak.ParseUsers` directly. E2E tests in
`test/test.js` cover all HTTP endpoints against a live stack using Mocha and Chai.

```sh
# Unit tests only (no stack required)
go test -v -race ./...

# E2E tests (full stack required — see Development Commands above)
npm --prefix test test
```

## Deployment

The application is containerized. Tekton pipelines in `.tekton/` build and push the image to
`quay.io/redhat-user-workloads/hcm-eng-prod-tenant/mocktitlements-master/mocktitlements-master` on
every push to `master`. The legacy `build_deploy.sh` script targets the older
`quay.io/cloudservices/mocktitlements` registry and is no longer used by CI.

[architecture]: ./ARCHITECTURE.md
[readme-dev]: ./README.md#development
