# Architecture

## Purpose & Scope

`mocktitlements` is a lightweight HTTP mock service that replicates two Red Hat Hybrid Cloud Console
backend APIs for local development and integration testing:

1. **Entitlements API** (`/api/entitlements/v1/`) — returns per-user service entitlements and
   compliance status.
2. **Service Accounts API** (`/auth/realms/redhat-external/apis/service_accounts/v1`) — provides
   CRUD operations for Keycloak-backed service accounts.

The service is not a proxy. It performs real reads and writes against a Keycloak instance
(typically a locally-running container), translating Keycloak's admin API responses into the shapes
that Console platform microservices expect. It has no database of its own; Keycloak is the sole
source of truth for both user data and service account state.

**Out of scope:** token issuance, authorization enforcement, and any persistence beyond Keycloak.
The service explicitly does not validate OAuth2 bearer-token scopes on incoming requests (noted as
a `// MUST VALIDATE` TODO in `main.go`).

---

## Request Flow

```
Client
  │
  │  HTTP request (port 8090)
  ▼
main.go — net/http default mux
  │
  ├─ GET /                              → statusHandler (empty 200)
  ├─ GET|POST /api/entitlements/v1/services   → entitlements()
  ├─ GET|POST /api/entitlements/v1/compliance → compliance()
  └─ * /auth/realms/redhat-external/apis/service_accounts/v1*
                                        → sa.ServiceAccountHandler()
                                              │
                                              ├─ GET    → getServiceAccounts()
                                              ├─ POST   → createServiceAccount()
                                              ├─ DELETE → deleteServiceAccount()
                                              └─ OPTIONS → optionsServiceAccount()
```

For entitlement and compliance routes the flow is:

1. Extract and base64-decode the `x-rh-identity` header.
2. Unmarshal into `identity.XRHID` (from `platform-go-middlewares`).
3. Look up the username in Keycloak's user list (fetched fresh on every request).
4. Return the user's `newEntitlements` attribute as a JSON object, or `403` if the user is not
   found or the header is absent/malformed.

For service account routes, steps 1–2 are used only to extract `org_id` and `username`; the actual
data operations go directly to Keycloak's admin API.

---

## Component Overview

| File | Package | Responsibility |
|---|---|---|
| `main.go` | `main` | Server startup, global logger init, HTTP mux registration, thin handler functions |
| `keycloak/keycloak.go` | `keycloak` | Keycloak admin API client: user lookup, client CRUD, mapper creation, secret retrieval; `x-rh-identity` parsing |
| `serviceaccounts/service_accounts.go` | `serviceaccounts` | Service account HTTP handler; delegates all persistence to the `keycloak` package |

### Key types

**`keycloak.Instance`**
The central stateful object. Holds an `*http.Client` pre-configured with an OAuth2
client-credentials token source (auto-refreshing), the Keycloak base URL, and a structured logger.

**`keycloak.UsersSpec`**
Raw JSON shape returned by Keycloak's `/auth/admin/realms/redhat-external/users` endpoint. All
domain-specific data lives in `Attributes map[string][]string`.

**`keycloak.User`**
Parsed, typed representation of a platform user. Produced by `ParseUsers()` after attribute
validation and type conversion.

**`serviceaccounts.ServiceAccount`**
Wire shape for the service accounts API response (`id`, `clientId`, `secret`, `name`,
`description`, `createdBy`, `createdAt`).

**`keycloak.clientStruct`**
Internal type used only when POSTing a new OpenID Connect client to Keycloak. Not exposed
externally.

---

## Keycloak Integration

### Connection & authentication

`GetKeycloakInstance()` constructs a `golang.org/x/oauth2/clientcredentials.Config` that uses the
Keycloak `admin-cli` client with a **Resource Owner Password Credentials (ROPC)** grant against
the `master` realm:

```
POST {KEYCLOAK_SERVER}/auth/realms/master/protocol/openid-connect/token
  grant_type=password
  client_id=admin-cli
  username={KEYCLOAK_USERNAME}
  password={KEYCLOAK_PASSWORD}
```

The resulting `*http.Client` transparently re-fetches tokens when they expire. This client is then
used for every subsequent admin API call.

### Admin API surface used

| Operation | Method | Keycloak endpoint |
|---|---|---|
| List users (up to 2000) | GET | `/auth/admin/realms/redhat-external/users?max=2000` |
| Query users by attributes | GET | `/auth/admin/realms/redhat-external/users?enabled=true&q=…` |
| Fetch single user | GET | `/auth/admin/realms/redhat-external/users/{id}` |
| Create OIDC client | POST | `/auth/admin/realms/redhat-external/clients` |
| Fetch client by UUID | GET | `/auth/admin/realms/redhat-external/clients/{id}` |
| Get client secret | GET | `/auth/admin/realms/redhat-external/clients/{id}/client-secret` |
| Add protocol mapper | POST | `/auth/admin/realms/redhat-external/clients/{id}/protocol-mappers/models` |
| Get service-account user | GET | `/auth/admin/realms/redhat-external/clients/{id}/service-account-user` |
| Update user attributes | PUT | `/auth/admin/realms/redhat-external/users/{id}` |
| Delete client | DELETE | `/auth/admin/realms/redhat-external/clients/{id}` |

All calls go through the generic `doRequest()` helper, which marshals the request body, sets
`Content-Type: application/json`, executes the call via the OAuth2-backed client, and optionally
unmarshals the response.

### User attribute contract

Keycloak users must carry the following custom attributes, validated by `ParseUsers()`. Any user
missing one or more is silently filtered out and not surfaced to callers.

| Attribute key | Go type after parsing | Notes |
|---|---|---|
| `is_active` | `bool` | Parsed with `strconv.ParseBool` |
| `is_org_admin` | `bool` | |
| `is_internal` | `bool` | |
| `account_id` | `int` | Maps to `User.ID` |
| `org_id` | `int` | |
| `account_number` | `string` | |
| `entitlements` | `string` (presence check only) | Must exist; actual entitlements data is in `newEntitlements` |
| `newEntitlements` | `[]string` | Raw JSON entitlement fragments, joined and returned as-is |

The `entitlements` attribute key exists only for presence validation; the actual entitlement
payload is stored in `newEntitlements` as a multi-valued string slice of raw JSON fragments (e.g.,
`"\"ansible\":{\"is_entitled\":true,\"is_trial\":false}"`). These are concatenated with commas and
wrapped in `{}` to produce the final JSON object.

---

## Service Accounts Subsystem

There is **no in-memory store**. Every service account operation is a live round-trip to Keycloak.
The "service accounts" that this API manages are modelled as Keycloak OIDC clients with
service-account users.

### Identity model

A service account is represented in Keycloak as:

- An OIDC **client** (with `serviceAccountsEnabled: true`, `clientId` = a newly-generated UUID,
  `name` = caller-supplied name).
- A system-generated **service-account user** (`service-account-{clientId}`) that Keycloak
  auto-creates.
- A set of **custom attributes** written to the service-account user to attach platform metadata:

| Attribute | Value |
|---|---|
| `org_id` | From `x-rh-identity` internal org ID |
| `service_account` | `"true"` (flag for query filtering) |
| `client_id` | The client UUID |
| `created_by` | Username from `x-rh-identity` |
| `description` | Caller-supplied description |
| `newEntitlements` | Copied from the creating user's own entitlements |

Six OIDC protocol mappers are also registered on the client (`org_id`, `service_account`,
`client_id`, `created_by`, `description`, `newEntitlements`) so those attributes appear in tokens
issued by this client.

### CRUD flow

**Create** (`POST …/service_accounts/v1`)

1. Generate a UUID (`github.com/google/uuid`).
2. Create the Keycloak OIDC client with that UUID as both `id` and `clientId`.
3. Fetch the created client to obtain its internal UUID (Keycloak may rewrite it).
4. Create the six protocol mappers.
5. Fetch the auto-generated service-account user.
6. Look up the requesting user to inherit their `newEntitlements`.
7. Patch the service-account user with the custom attributes.
8. Return `201` with a `ServiceAccount` JSON body.

**List** (`GET …/service_accounts/v1?first=N&max=M`)

Queries Keycloak users with `q=org_id:{orgID} AND service_account:true`, passing through any query
parameters (e.g., `first`, `max`) as-is. For each result, fetches the client secret separately.

**Get single** (`GET …/service_accounts/v1/{uuid}`)

Same query as list but adds `AND client_id:{uuid}`. Expects exactly one result; returns `404` if
zero or more than one are found.

**Delete** (`DELETE …/service_accounts/v1/{uuid}`)

Proxies a `DELETE` to `/auth/admin/realms/redhat-external/clients/{uuid}`. Returns `204` on
success, `404` if Keycloak returns 404.

**Routing disambiguation** (`getServiceAccounts`)

GET requests are dispatched by inspecting the last path segment: if it parses as a valid UUID, a
single-account lookup is performed; if query parameters are present, a list is returned; otherwise
a `400` is returned.

---

## Identity / Authentication Model

All authenticated routes require a `x-rh-identity` header containing a base64-encoded JSON object
conforming to the `identity.XRHID` structure from
`github.com/redhatinsights/platform-go-middlewares/identity`.

Minimal shape expected:

```json
{
  "identity": {
    "type": "User",
    "user": { "username": "jdoe" },
    "internal": { "org_id": "000001" }
  }
}
```

**Entitlements/compliance routes** require `identity.type == "User"` and a non-empty `username`.
The username is used as a lookup key against Keycloak's user list (matched on
`UsersSpec.Username`). Missing header, decode failure, unmarshalling failure, missing username, or
unrecognised username all result in `403`.

**Service account routes** only extract `identity.internal.org_id` and `identity.user.username`.
There is no type check or user-existence check at the handler boundary; the `org_id` is used
solely as a Keycloak query filter, and `username` is stored as `created_by`.

There is no session layer, no token validation, and no middleware chain. Identity parsing is
performed inline in each handler path.

---

## Configuration

All configuration is supplied via environment variables, read at startup:

| Variable | Default | Description |
|---|---|---|
| `KEYCLOAK_SERVER` | *(none)* | Base URL of the Keycloak server (e.g., `http://keycloak:8080`) |
| `KEYCLOAK_USERNAME` | `admin` | Admin username for ROPC grant against the `master` realm |
| `KEYCLOAK_PASSWORD` | `admin` | Admin password |

If `KEYCLOAK_SERVER` is not set, the OAuth2 token URL resolves to a relative path and will fail at
runtime. There is no validation or startup check. The HTTP server always listens on `:8090`
(hardcoded in `main.go`). Logging is always initialised in development mode (`zap.NewDevelopment`)
with no log-level configuration.

---

## Key Design Decisions & Tradeoffs

### No web framework

`net/http` is used directly with a catch-all handler and routing implemented as a `switch` on
`r.URL.Path` with a `strings.Contains` fallback for the service accounts subtree. This eliminates
external routing dependencies but makes URL parameter extraction manual (path splitting by `/`) and
provides no middleware composition, no automatic method-not-allowed responses, and no parameter
binding.

### Keycloak as the sole persistence layer

Rather than maintaining an in-memory or database-backed store, all state lives in Keycloak:

- **Correct:** service account data persists across restarts and matches what Keycloak itself
  returns.
- **Costly:** every list request issues N+1 HTTP calls (one user query + one `client-secret` fetch
  per result); every user lookup for entitlements fetches all users (up to 2000) on each request
  with no caching.
- **Coupled:** the service cannot start meaningfully without a reachable Keycloak instance; there
  is no fallback or graceful degradation.

### User list fetched per request

`getUsers()` issues a fresh `GET /users?max=2000` on every entitlements/compliance request. There
is no in-process cache, TTL, or background refresh. At scale this is a bottleneck, but for the
development/test use case the simplicity is intentional.

### Service account entitlements inherited at creation time

When a service account is created, the creating user's `newEntitlements` are copied into the
service-account user's attributes at creation time rather than read dynamically. If the user's
entitlements change after creation, the service account's entitlements become stale.

### OAuth2 ROPC grant (not client credentials)

Despite using `golang.org/x/oauth2/clientcredentials`, the grant type is overridden to `password`
via `EndpointParams`. This is the Keycloak admin-cli pattern but relies on direct credential access
to Keycloak, which is a security concern in any non-local environment.

### Delete proxies raw request URL (latent bug)

`deleteServiceAccount()` constructs the delete URL using the incoming request's path rather than
the remapped admin path. The path rewrite to `/auth/admin/realms/redhat-external/clients/{id}` is
applied to a local variable but not to the actual URL used in the request. Whether this works in
practice depends on Keycloak's routing behaviour.

### Permissive CORS

All service account responses include `Access-Control-Allow-Origin: *` with broad method and
header allowlists. This is appropriate for a development mock but would be a misconfiguration in
production.

### No scope validation

A `// MUST VALIDATE THAT THE BEARER TOKEN HAD THE RIGHT SCOPES` comment in `main.go` documents a
known omission. Requests with any `x-rh-identity` header that resolves to a known user are
accepted regardless of OAuth2 scopes.
