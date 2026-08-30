# P1 Team isolation — architecture (P1.0) and kernel scope (P1.1)

Canonical Team design. Agent state stays in `docs/agent/`. Do not duplicate this file there.

**Status:** P1.0 accepted. P1.1 isolation kernel is implemented on `feat/p1-isolation-kernel` (migration + pure repository + adversarial tests). P1.2+ (OIDC, RBAC HTTP, UI, sessions, audit tables) are out of scope until explicitly requested.

**Decided 2026-08-30:**

1. Team OIDC is fully separate from Grok Better Auth. `VITE_AUTH_ENABLED=false`. Team code must not import or call `authMiddleware` or `requireUserId`.
2. P1 does not upload or store raw HAR, raw HTTP, JWT compact tokens, cookie values, or credentials. The server may persist policy, review state, and a deep-redacted ReportDTO only. Sharing captures is a later phase after a threat-model update and encryption design.

---

## 1. Threat boundary

| Mode | Trust | Persistence | Network |
|------|--------|-------------|---------|
| **Solo (default)** | Analyst workstation. Engine in-browser. | Optional `localStorage` key `claimforge-v2`. Captures never leave the tab except user-initiated JWKS fetch. | None required. |
| **Team (opt-in, self-hosted)** | Tenant members after **verified** membership. Engine still in-browser. | Postgres/PGLite rows scoped by `tenant_id` from a **verified TenantContext**. | Customer IdP (P1.2+). No Grok broker. |

Platform chrome (Better Auth, Grok identity, `__Host-grok-auth.*`, `src/lib/auth/*`) is **not** the Team identity plane. It stays disabled.

Victim lab (`/api/lab/*`, `lab_revoke`) is an unowned demo API. It is not a tenant resource. Team queries must never join lab tables.

### What an attacker must not achieve

- Read or write another tenant's workspace, membership, or collab payload by sending `tenant_id` in body, query, header, or an unlinked JWT claim.
- Create the first tenant/owner through a public endpoint.
- Persist capture secrets on the Team server.
- Use Grok/preview `dev-user` or `requireUserId` as a Team actor (fail-closed when `DATABASE_URL` is set and auth is off — see `verify.server.ts`).
- Infer whether a workspace id exists in another tenant (fail-closed not-found).

### What the server does **not** control

Raw loot/replay/curl export runs in the **browser** from the in-memory workspace. Server RBAC (P1.3+) can refuse to **store or return** loot/replay fields from ReportDTO; it cannot honestly claim to prevent a Solo or still-local Team tab from copying those strings. Document that split in every UI and ADR. In-browser export of raw loot is a local analyst action, not a Team authorization decision.

---

## 2. Tenant context (source of truth)

`tenant_id` is **never** taken from:

- request body
- query string
- arbitrary headers (`X-Tenant-Id`, `Tenant`, …)
- JWT / OIDC claims that have not been **linked** to a `team_member` row by server-side lookup

Construction of `TenantContext` is branded (runtime symbol). A plain object `{ tenantId, userKey, role }` is rejected. `contextFromMember` is **not** a public API: a `TeamMember` row object is not a context, and no exported factory will brand an arbitrary member.

Legal factories (P1.1) — both stamp the brand only after SQL:

1. **Bootstrap** (admin process): `unlockBootstrap(providedSecret, configuredSecret)` → `BootstrapActor` → `bootstrapTenant` inserts tenant + first owner in one transaction and returns a context built from the **inserted member row**.
2. **Membership resolve:** `resolveTenantContext(sql, userKey, requestedTenantId?)` `SELECT`s `team_member`. The effective `tenantId` / `userKey` / `role` are copied from the **row**, not from the arguments. `requestedTenantId` is a disambiguation hint only; if the row is missing, fail closed (same as unknown tenant). If omitted and the user has one membership, use that row. If several, fail closed as ambiguous (do not pick arbitrarily).

Every repository function takes `TenantContext` (or `BootstrapActor` for bootstrap only) and **every** SQL statement includes `tenant_id = ctx.tenantId` from that verified object.

P1.2 will bind `user_key` from a verified OIDC `iss`+`sub` after signature/iss/aud checks, then call the same resolver. Unverified tokens never become context.

---

## 3. Schema (P1.1)

Product migration: `migrations/0003_team_isolation.sql` (globbed). Do **not** copy `migrations/auth/0001_auth.sql`.

```
team_tenant
  id TEXT PK
  slug TEXT UNIQUE NOT NULL
  name TEXT NOT NULL
  bootstrap_actor TEXT NOT NULL
  created_at TIMESTAMPTZ

team_member
  PRIMARY KEY (tenant_id, user_key)
  tenant_id → team_tenant(id) ON DELETE CASCADE
  role CHECK IN ('owner','admin','lead','analyst','viewer')

team_workspace
  PRIMARY KEY (tenant_id, id)
  tenant_id → team_tenant(id) ON DELETE CASCADE
  FOREIGN KEY (tenant_id, created_by_user_key) → team_member (tenant_id, user_key)

team_workspace_collab
  PRIMARY KEY (tenant_id, workspace_id)
  FOREIGN KEY (tenant_id, workspace_id) → team_workspace (tenant_id, id)
  FOREIGN KEY (tenant_id, updated_by_user_key) → team_member (tenant_id, user_key)
  policy_json, review_json, report_dto_json  -- allowed persist only
```

Composite primary keys and composite FKs make a workspace or collab row physically unable to reference a member or workspace of another tenant.

The same `user_key` **may** belong to multiple tenants (separate member rows). Isolation is `(tenant_id, user_key)`, not `user_key` alone.

**Not in P1.1:** session tables, OIDC client/secret tables, audit tables, RLS policies.

---

## 4. Bootstrap (first tenant / first owner)

Creating a tenant and assigning the first `owner` is an **operator procedure**, not a public API.

- Requires `BootstrapActor` from `unlockBootstrap`. The configured secret is supplied by the operator environment (length ≥ 16). Comparison is timing-safe. Empty/missing configured secret means bootstrap is disabled.
- There is no HTTP route in P1.1. P1.2+ must not add `POST /api/team/tenants` that lets a caller become `owner` without this unlock.
- Tenant insert + owner insert are one transaction. Failure rolls back both (no ownerless tenant, no member without tenant).
- Subsequent members are added only through a verified `TenantContext` of **that** tenant. P1.1 does not yet enforce which roles may add members (RBAC is P1.3); isolation still prevents adding a member to a different tenant.

---

## 5. Allowed vs forbidden persist

| Allowed | Forbidden (reject at repository write) |
|---------|----------------------------------------|
| `AnalysisPolicy` JSON (patterns validated) | `aRaw`, `bRaw`, `requests`, HAR `log.entries` |
| Review map `fingerprint → ReviewState` | JWT compact tokens, `jwt.raw` / payload / signature |
| ReportDTO with `secrets: "redacted"` and schema version | Cookie values, `Authorization` / `Cookie` / API keys |
| Workspace name, ids, role enum | PEM private keys, credential-shaped canaries |
| | `tenantId` / `tenant_id` on caller persist input (spoof) |

`updateWorkspaceCollab` runs `assertAllowedCollab` before SQL. ReportDTO is a **strict runtime schema** (unknown fields rejected), then deep-redacted again into a **new** object, then size-capped. Policy and review are allowlisted the same way. Compact-JWT shaped strings, live Bearer tokens, PEM, HAR `log.entries`, raw HTTP outside `replays.raw`/`curl`, `api_key` / `sessionSecret`, and oversize Base64 fail closed and write nothing.

Read path (`getCollab`) re-parses stored JSON through the same sanitizer. A tampered row is `TeamPersistError`, not returned.

Collab writes are a single `INSERT ... ON CONFLICT (tenant_id, workspace_id) DO UPDATE` so two first-writes cannot 23505 or split a row.

UTF-8 byte caps: policy 64KiB, review 64KiB, ReportDTO 512KiB; string/fingerprint/array lengths are bounded.

ReportDTO may still contain **redacted** loot/replay placeholders. That is not permission to store raw secrets. Deep-redaction canaries from P0.2 apply.

---

## 6. Security invariants (tested in P1.1)

1. Forged `TenantContext` (no brand) is rejected.
2. `tenant_id` on input objects is rejected; queries use `ctx.tenantId` only.
3. Cross-tenant read/update/delete of workspace or collab → not-found (no existence leak).
4. Cross-tenant composite FK insert → database reject.
5. Same `user_key` in two tenants cannot see the other tenant's rows.
6. Missing id and other-tenant id are indistinguishable.
7. Failed migration transaction leaves no Team tables (no half-applied 0003).
8. Lab `lab_revoke` and Solo analyze/export paths do not import Team and still behave.
9. Team modules do not import `authMiddleware` / `requireUserId` / `@/lib/auth/server`.
10. Auth schema `0001_auth.sql` remains outside `migrations/` glob.

---

## 7. Deferred (specified now, not built)

### OIDC (P1.2)

Authorization Code + PKCE. JWKS fetch reuses `inspectJwksUrl` / `fetchJwksDocument` with `teamMode: true` and a closed hostname allowlist. No `createRemoteJWKSet`.

**Client secrets:** P1.1 stores none. When P1.2 persists IdP config, `client_secret` must live in a secret manager **or** envelope-encrypt with a server-managed key (env/KMS). Plaintext secrets in Postgres are forbidden.

### Sessions (P1.2)

Opaque random token (cryptographic RNG). Database stores only a **hash** of the token, plus expiry, rotation, and revoke. Presenting the raw token in a cookie (`__Host-claimforge-team.session`) is allowed; storing the raw token is not.

### Audit (P1.4)

Append-only. No capture bodies, no JWKS material. **Do not store a plain hash of client IP** (low entropy, rainbow-tableable). Either omit IP or store `HMAC(ip, rotating_server_key)` with key rotation and no raw IP alongside. User-agent similarly: omit or HMAC.

### RBAC HTTP (P1.3)

Role on the **member row** is authoritative. A JWT `role=admin` claim is not. Viewer cannot mutate. `accepted-risk` requires lead+. Server may refuse to persist loot/replay; it does not control in-browser copy.

### Postgres RLS

PGLite tests prove application-level isolation and constraints. **Neon/Postgres RLS is defense-in-depth**, not the P1.1 bar. Call the kernel “stable” for RLS only after a dedicated integration test against real Postgres. Do not claim RLS is enforced until that test exists.

### CI vs merge policy

GitHub Actions `ci` / `gates` currently runs on `push` to `main` and on `pull_request`. **`main` has no branch protection / ruleset** at the time of this spec. Passing CI is evidence the HEAD was green; it is **not** merge-enforced until a ruleset requires the `ci` / `gates` check. Do not describe CI as a merge gate before that.

---

## 8. P1.1 deliverable (this slice)

- This document + ADRs in `docs/agent/DECISIONS.md`
- Migration `0003_team_isolation.sql`
- Pure repository layer `src/lib/team/*` (no HTTP, no UI)
- Adversarial tests + `p1-gates.ts`
- Solo/Lab regression tests

Out of scope: OIDC routes, session cookies, RBAC middleware, Team UI, audit table, capture upload.
