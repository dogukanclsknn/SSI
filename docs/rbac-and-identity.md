# RBAC & Identity — Design and Activation

**Status:** Phase 5 · Identity & Authorization. Role/permission model, central
enforcement, signed sessions (LDAP / local admin), proxy identity and `/session` are
implemented.

## Goal

Replace the "two strings" approval simulation with real **role-based authorization**:
who may plan, request, approve and administer is decided by roles, and every decision
is recorded in the audit trail.

## Model

**Roles → permissions** (`src/lib/rbac.js`, pure and tested):

| Role | Permissions (summary) |
|---|---|
| `viewer` | All reads (`*:read`) |
| `operator` | Reads + `remediation:plan/manage`, `remediation:accept`, `onboarding:create`, `publish:request`, `exception:request` |
| `approver` | Reads + `publish:approve`, `exception:approve`, `remediation:accept` |
| `admin` | Everything (wildcard `*`) |

**Separation of duties:** `publish:request` (operator) and `publish:approve`
(approver) are different roles. The backend additionally enforces requester ≠
approver — authorization plus identity, two layers of defence.

**Publish decisions after the policy evaluation:** `publish:approve` also covers
rejecting a request that waits for approval (`POST /publish-requests/{id}/reject`) and
withdrawing a published image (`POST /publish-requests/{id}/withdraw`). A withdrawal is
decided by one authorized person (stopping a bad image must be fast); the reason and
category are mandatory and audited, and the digest can never be published again.

**Pre-release consumer acceptance:** `remediation:accept` lets a consumer team member
mark a verified candidate as "Tested — OK" or report an issue
(`POST /remediation/{id}/consumer-acceptance`). Operators and approvers carry it, because
the person who tried the image is often not an operator. The decider is always the
trusted session identity; the publish policy forbids the publish requester to be the one
who accepted (four-eyes rule).

## Enforcement (fail-closed, config-gated)

A single **choke-point**: every request in `handleApi` is checked against the
permission mapped to its route (`permissionForRoute`, unmapped routes default to
`system:admin`). Exempt routes (`/health`, `/session` and machine-to-machine HMAC/token
endpoints: worker-evidence, worker-supply-chain-evidence, worker-candidate-test, receipts, import-receipt,
worker-handoff) carry their own
authentication.

- `SSI_RBAC_ENFORCED=true` (**default**): no identity → `401`, missing permission →
  `403`. Refusals are written to the audit trail as `rbac.access.denied`.
- `SSI_RBAC_ENFORCED=false` (explicit, isolated labs only): nothing is blocked; every
  caller gets `SSI_RBAC_DEFAULT_ROLES`. The subject from a trusted source is still audited.

**Teams (multi-tenancy):** `/tenants` requires `tenant:manage`, which only the admin
wildcard carries. With `SSI_MULTI_TENANCY=true` the tenant context is resolved *before*
this check and the caller's role in the selected team replaces the global role, so the
same permission map decides inside the team; a permissioned route without a selected
team is refused (400 select a team / 403 no team) and audited as `tenancy.access.denied`.
Worker callbacks stay exempt and act in the team of the record they name. Details:
`docs/multi-tenancy.md`.

**Two-person rule:** publish approvals and risk acceptances always require an approver
other than the requester (`SSI_PUBLISH_REQUIRE_SEPARATE_APPROVER`, default `true`; risk
acceptances enforce it unconditionally, down to a database constraint).

## Where identity comes from

`src/server/identity.js > resolveIdentity` is the single source. It returns
`{ subject, roles, permissions, authenticated, enforced, source }`. Sources, in
precedence order:

| # | `source` | Enabled by | Subject | Roles |
|---|---|---|---|---|
| 1 | `session` | `SSI_SESSION_SECRET` + LDAP or local admin sign-in | Signed session cookie | Read **live** from the user store (role change / disable applies immediately) |
| 2 | `proxy` | `SSI_TRUST_ACTOR_HEADER=true` | `X-Forwarded-User` | Server-side only: `X-Forwarded-Groups` → `SSI_RBAC_GROUP_ROLE_MAP`, else `SSI_RBAC_ROLE_BINDINGS` |
| 3 | `dev-login` | `SSI_DEV_LOGIN=true` | `X-SSI-Actor-Id` | `X-SSI-Actor-Roles`, else `SSI_RBAC_ROLE_BINDINGS` |
| 4 | `anonymous` | — | — | none (→ `401`) |

Security properties:

- **No client-asserted roles in production.** `X-SSI-Actor-Id` / `X-SSI-Actor-Roles`
  are honoured **only** in dev-login mode. With proxy trust enabled, a client that adds
  `X-SSI-Actor-Roles: admin` gets nothing — roles come from the group map.
- A proxy-authenticated user cannot be replaced by `X-SSI-Actor-Id`; if both proxy and
  dev login are (mis)configured, the proxy identity wins.
- A user known to the proxy but mapped to no role is authenticated with **no
  permissions** (fail-closed).
- `trustedActor` (used by publish and risk-acceptance flows) is true only for the
  `session`, `proxy` and `dev-login` sources (`isTrustedIdentity`).

## `GET /api/v1/session`

Lets the UI learn the current user and effective permissions:
```json
{ "subject": "sam", "displayName": "Sam", "roles": ["approver"],
  "permissions": ["...", "publish:approve"], "authenticated": true, "enforced": true,
  "devLogin": false, "passwordLogin": true,
  "tenancy": { "enabled": false, "tenantId": "default", "platformAdmin": false, "teams": [] } }
```
With multi-tenancy on, `roles`/`permissions` are those of the selected team and
`tenancy.teams` lists the caller's active teams with their role (every team for a
platform administrator). A refused `X-SSI-Tenant` does not fail `/session`: the answer
falls back to no selection and carries `tenancy.selectionError`.
The UI hides or disables controls based on these permissions. With enforcement off the
permissions are `["*"]`.

## Dev / demo login

A flagged identity picker for showing RBAC without SSO. **It is not
authentication** — the user picks their own role — and must stay off in production.
The server logs a warning at start-up while it is enabled.

```
SSI_DEV_LOGIN=true
SSI_RBAC_ENFORCED=true
```
The UI then shows a picker (user + role), `api.js` sends `X-SSI-Actor-Id` +
`X-SSI-Actor-Roles` with every request, and the server enforces RBAC against them.
`SSI_TRUST_ACTOR_HEADER` is **not** needed for dev login. When a password login (LDAP /
local admin) is available the UI shows the real sign-in form instead.

## Production identity: LDAP / local admin sessions

LDAP **authenticates only**; the user's **role** is held in SSI and assigned by an
admin on the Users screen. Required: `SSI_RBAC_ENFORCED=true`, `SSI_SESSION_SECRET`,
`LDAP_*` and/or `SSI_LOCAL_ADMIN_*`, `SSI_DEV_LOGIN=false`.

### Session and sign-in hardening

- **Secret:** `SSI_SESSION_SECRET` is required when LDAP or the local admin is
  configured and must be at least 32 bytes; otherwise SSI refuses to start.
- **Tokens:** HMAC-SHA256 signed, 8-hour lifetime, each with a random `jti` and `iat`.
  Tokens without a `jti` are rejected.
- **Sign-out:** `POST /api/v1/auth/logout` revokes the token's `jti` server-side
  (`session_revocations`, migration `006`) until it would have expired, so a copied
  cookie stops working immediately and stays revoked across restarts. Audited as
  `auth.logout`.
- **Uniform failures:** every credential failure returns the same `401 Incorrect
  username or password.`; an unknown username costs the same scrypt work as a real
  one, so neither status nor timing reveals which accounts exist.
- **Throttling:** 5 failed sign-ins per username or 50 per client address (TCP peer,
  never a forwarded header) within 15 minutes → `429` with `Retry-After`. Audited as
  `auth.login.throttled`. A successful sign-in clears the username counter.
- **Password checks** use asynchronous scrypt, so they never block the event loop.

## Production identity: oauth2-proxy + Microsoft Entra ID

**Decision:** the identity provider is **Entra ID (Azure AD)**. Existing Entra groups
map to SSI roles. [oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/) sits in
front of SSI, authenticates the user with Entra ID and passes identity/groups as
headers.

**Runnable configuration** lives in `deploy/oauth2-proxy/` (compose overlay,
`oauth2-proxy.cfg`, sample env, README). Verified version: **oauth2-proxy v7.15.4**
(Aug 2026), `provider=entra-id`.

**Flow:** user → oauth2-proxy (Entra ID OIDC) → SSI. With `pass_user_headers` the proxy
sends `X-Forwarded-User` and `X-Forwarded-Groups` upstream; SSI maps groups to roles
with `SSI_RBAC_GROUP_ROLE_MAP`.

Run (from the repo root):
```
docker compose -f docker-compose.yml \
  -f deploy/oauth2-proxy/docker-compose.oauth2-proxy.yml up -d --build
```

SSI env behind the proxy. Entra sends group **GUIDs** in the groups claim, so the map
keys are GUIDs:
```
SSI_RBAC_ENFORCED=true
SSI_TRUST_ACTOR_HEADER=true
SSI_DEV_LOGIN=false
SSI_RBAC_GROUP_ROLE_MAP=<approver-group-guid>:approver, <operator-group-guid>:operator, <viewer-group-guid>:viewer
```

**Entra-side tasks (1 registration + 2 decisions):**
1. An **App Registration** in Entra ID (redirect URI = oauth2-proxy callback) and a
   client secret.
2. **Groups claim** in the token: App Registration → Token configuration → *groups
   claim* (GUIDs by default).
3. **Group → role** mapping: which existing groups are `approver/operator/viewer/admin`.

**Security:** the proxy must **strip** inbound `X-Forwarded-*` and `X-SSI-Actor-*`
headers and inject only the values it verified. Direct (proxy-less) access to SSI must
be closed at the network level — see `deploy/oauth2-proxy/README.md`.

> Sources: [oauth2-proxy — Microsoft Entra ID provider](https://oauth2-proxy.github.io/oauth2-proxy/configuration/providers/ms_entra_id/), [oauth2-proxy — configuration overview (pass-user-headers)](https://oauth2-proxy.github.io/oauth2-proxy/configuration/overview/).
