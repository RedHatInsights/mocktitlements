# mocktitlements

A lightweight Go HTTP server that mocks the Red Hat Entitlements and Service Accounts APIs for
local development and integration testing. It authenticates requests against a real Keycloak
instance and returns entitlement data sourced from Keycloak user attributes.

For internal design details, see the [project architecture][architecture].

## Prerequisites

| Tool | Version | Notes |
|---|---|---|
| Go | 1.25 | See [`.tool-versions`][tool-versions] |
| Node.js | 24 | Required for E2E tests only |
| golangci-lint | latest | Required for linting |
| Docker or Podman | any recent | Required to run the full stack |

All runtime tool versions are pinned in [`.tool-versions`][tool-versions] for use with
[asdf][asdf].

## API endpoints

The server listens on port `8090`. All endpoints that look up a user require a base64-encoded
`x-rh-identity` header.

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Health / status (always `200`) |
| `POST` | `/api/entitlements/v1/services` | Returns entitlements for the authenticated user |
| `POST` | `/api/entitlements/v1/compliance` | Returns compliance status for the authenticated user |
| `GET` | `/auth/realms/redhat-external/apis/service_accounts/v1` | Lists service accounts (`first` / `max` query params supported) |
| `POST` | `/auth/realms/redhat-external/apis/service_accounts/v1` | Creates a new service account |
| `GET` | `/auth/realms/redhat-external/apis/service_accounts/v1/:clientId` | Gets a single service account by UUID |
| `DELETE` | `/auth/realms/redhat-external/apis/service_accounts/v1/:clientId` | Deletes a service account |

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `KEYCLOAK_SERVER` | _(required)_ | Base URL of the Keycloak instance (e.g. `http://localhost:8080`) |
| `KEYCLOAK_USERNAME` | `admin` | Keycloak admin username |
| `KEYCLOAK_PASSWORD` | `admin` | Keycloak admin password |

In the Docker Compose environment the password is set to `change_me` — see
[`deployments/compose.yaml`][compose-yaml].

## Running with Docker Compose

The full stack (mocktitlements + Keycloak + PostgreSQL) is defined in
[`deployments/compose.yaml`][compose-yaml].

```sh
docker compose -f deployments/compose.yaml up -d --build
```

**SELinux systems (Fedora, RHEL, etc.):** volume mounts require additional SELinux labels. Use the
provided env file:

```sh
docker compose -f deployments/compose.yaml --env-file deployments/podman-compose-env up -d --build
```

After starting the stack, Keycloak must finish importing the `redhat-external` realm before the
application is usable. The CI pipeline uses [`deployments/wait_for_keycloak_import.sh`][wait-script]
to poll for readiness.

## Development

### Unit tests

```sh
go test -v -race ./...
```

### Linting

```sh
golangci-lint run
```

Lint rules are configured in [`.golangci.yml`][golangci-yml] (47 linters enabled).

### E2E tests

Tests are written in JavaScript using [Mocha][mocha] and [Chai][chai] and run against the live
stack.

**1. Install Node dependencies:**

```sh
npm i --save-dev --prefix test
```

**2. Start the stack** (see [Running with Docker Compose][running] above).

**3. Run the tests:**

```sh
npm --prefix test test
```

### Iterating locally

When Keycloak and PostgreSQL are already running, you can rebuild and retest only the mocktitlements
container without restarting the full stack:

```sh
./rebuild_and_test.sh
```

### Debugging E2E tests in VSCode

Create a launch configuration in `.vscode/launch.json`:

```json
{
    "version": "0.2.0",
    "configurations": [
       {
          "type": "node",
          "request": "launch",
          "name": "Debug Mocha Tests",
          "program": "${workspaceFolder}/test/node_modules/mocha/bin/_mocha",
          "args": [
             "test.js"
          ],
          "cwd": "${workspaceFolder}/test",
          "console": "integratedTerminal",
          "internalConsoleOptions": "openOnSessionStart"
       }
    ]
 }
```

Run the **Debug Mocha Tests** task in VSCode to execute the suite with breakpoint and variable
inspection support.

## Container image

The image is built from [`Dockerfile`][dockerfile] using a two-stage build (UBI9 go-toolset
builder → UBI9 minimal runtime). The published image is available at
[`quay.io/cloudservices/mocktitlements`][quay-image].

[running]: #running-with-docker-compose
[architecture]: ./ARCHITECTURE.md
[tool-versions]: ./.tool-versions
[compose-yaml]: ./deployments/compose.yaml
[wait-script]: ./deployments/wait_for_keycloak_import.sh
[golangci-yml]: ./.golangci.yml
[dockerfile]: ./Dockerfile
[quay-image]: https://quay.io/repository/cloudservices/mocktitlements
[asdf]: https://asdf-vm.com
[mocha]: https://mochajs.org
[chai]: https://www.chaijs.com
