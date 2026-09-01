# P1 Team isolation — architecture (P1.0) and kernel scope (P1.1)

Canonical Team design. Agent state stays in `docs/agent/`. Do not duplicate this file there.

**Status:** P1.0 accepted. P1.1–P1.7 are on `main` (P1.7 PR #7 `9cbd88d`). Encrypted capture share is not P1.

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

Construction of `TenantContext` is branded (runtime symbol) **and** registered in a module-private `WeakMap<TenantContext, BoundIdentity>`. Both the context object and the snapshot are `Object.freeze`d. A plain object `{ tenantId, userKey, role }` is rejected. Copying the brand symbol onto a new object is rejected (it is not in the WeakMap). `contextFromMember` is **not** a public API.

Legal factories (P1.1) — both stamp the brand and register the WeakMap snapshot only after SQL:

1. **Bootstrap** (admin process): `unlockBootstrap(providedSecret, configuredSecret)` → frozen `BootstrapActor` in a WeakMap → `bootstrapTenant` inserts tenant + first owner in one transaction and returns a context built from the **inserted member row**.
2. **Membership resolve:** `resolveTenantContext(sql, userKey, requestedTenantId?)` `SELECT`s `team_member`. The effective `tenantId` / `userKey` / `role` are copied from the **row**, not from the arguments. `requestedTenantId` is a disambiguation hint only; if the row is missing, fail closed (same as unknown tenant). If omitted and the user has one membership, use that row. If several, fail closed as ambiguous (do not pick arbitrarily).

Every public repository function calls `requireActiveMember`: read the frozen WeakMap snapshot (never `ctx.tenantId` / `ctx.userKey` / `ctx.role` as SQL authority), then `SELECT` `team_member` for that pair. Missing membership is fail-closed `not found`. Live `role` comes from the row. SQL uses the snapshot/row ids only.

P1.2 binds `user_key` from a verified OIDC `iss`+`sub` (`oidc:` + sha256 of `JSON.stringify([iss, sub])`) after signature/iss/aud/azp/exp/iat/nonce checks, then calls the same resolver. Unverified tokens never become context. JWT `tenant_id` / `role` claims are ignored.

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

**Not in P1.1:** session tables, OIDC client/secret tables, audit tables, RLS policies. P1.2 adds `team_oidc_pending` and `team_session` in `migrations/0004_team_oidc_sessions.sql` without rewriting `0003`. P1.4 adds `team_audit` in `migrations/0005_team_audit.sql` without rewriting `0003` or `0004`.

---

## 4. Bootstrap (first tenant / first owner)

Creating a tenant and assigning the first `owner` is an **operator procedure**, not a public API.

- Requires `BootstrapActor` from `unlockBootstrap`. The configured secret is supplied by the operator environment (`CLAIMFORGE_TEAM_BOOTSTRAP_SECRET`, length ≥ 16). Comparison is timing-safe. Empty/missing configured secret means bootstrap is disabled.
- There is no HTTP route. P1.2 ships `npm run team:bootstrap` (see [docs/operator/BOOTSTRAP.md](./operator/BOOTSTRAP.md)). It requires `DATABASE_URL` (no PGLite fallback), reads the bootstrap secret from the environment (never argv), derives `user_key` with `oidcUserKey(issuer, sub)`, and runs `unlockBootstrap` + `bootstrapTenant` in one TeamSql transaction. Do not add `POST /api/team/tenants` that lets a caller become `owner` without this unlock.
- CLI stdout is tenant id, slug, and derived `user_key` only. It must not log the bootstrap secret, client secret, tokens, or raw `sub`.
- Fail-closed if input/env is missing, `team_tenant` / `team_member` are not migrated, or the slug already exists.
- Tenant insert + owner insert are one transaction. Failure rolls back both (no ownerless tenant, no member without tenant).
- Subsequent members are added only through a verified `TenantContext` of **that** tenant. P1.3 enforces who may add/change/remove members (admin+, no assigning `owner`, last owner protected). Isolation still prevents adding a member to a different tenant.

---

## 5. Allowed vs forbidden persist

| Allowed | Forbidden (reject at repository write) |
|---------|----------------------------------------|
| `AnalysisPolicy` JSON (patterns validated) | `aRaw`, `bRaw`, `requests`, HAR `log.entries` |
| Review map `fingerprint → ReviewState` | JWT compact tokens, `jwt.raw` / payload / signature |
| ReportDTO with `secrets: "redacted"` and schema version | Cookie values, `Authorization` / `Cookie` / API keys |
| Workspace name, ids, role enum | PEM private keys, credential-shaped canaries |
| | `tenantId` / `tenant_id` on caller persist input (spoof) |

`updateWorkspaceCollab` runs `assertAllowedCollab` before SQL. Incoming ReportDTO is a **strict runtime schema** (unknown fields rejected). The server then **projects** a new Team object: `loot.value`, `replays.raw`, and `replays.curl` are always `[redacted]`. That projection is re-parsed as a closed Team schema, deep-redacted into another new object, then UTF-8/element capped. Client `secrets: "redacted"` is not trusted as proof that remaining strings are clean.

Regex canaries are defense-in-depth after projection (Bearer, Basic, Cookie, compact JWT, PEM, `curl -u` / `curl --user`, AWS `AKIA…`, oversize Base64, raw HTTP). They do not replace the projection.

Read path (`getCollab`) re-parses stored JSON as the **Team** schema. A tampered row (live loot/replay blobs, unknown fields, canary hits) is `TeamPersistError`, not returned.

Collab writes are a single `INSERT ... ON CONFLICT (tenant_id, workspace_id) DO UPDATE` so two first-writes cannot 23505 or split a row.

UTF-8 byte caps: policy 64KiB, review 64KiB, ReportDTO 512KiB; string/fingerprint/array lengths are bounded.

---

## 6. Security invariants (tested in P1.1)

1. Forged `TenantContext` (no brand / not in WeakMap) is rejected.
2. `tenant_id` on input objects is rejected; queries use the frozen WeakMap snapshot, never caller `ctx.tenantId`.
3. Cross-tenant read/update/delete of workspace or collab → not-found (no existence leak).
4. Cross-tenant composite FK insert → database reject.
5. Same `user_key` in two tenants cannot see the other tenant's rows.
6. Missing id and other-tenant id are indistinguishable.
7. Failed migration transaction leaves no Team tables (no half-applied 0003).
8. Lab `lab_revoke` and Solo analyze/export paths do not import Team and still behave.
9. Team modules do not import `authMiddleware` / `requireUserId` / `@/lib/auth/server`.
10. Auth schema `0001_auth.sql` remains outside `migrations/` glob.
11. Mutating a minted context or copying its brand symbol cannot retarget tenant SQL.
12. A context whose membership row was deleted cannot be reused.
13. Team persist is a projection: loot values and replay raw/curl are always `[redacted]` in stored JSON.
14. Unverified OIDC tokens never become `TenantContext`; JWT `tenant_id`/`role` claims are ignored.
15. Unknown OIDC subject is 404; no JIT `team_member`.
16. Session DB stores token hash only; deleted members cannot reuse a session.
17. Team OIDC is HTTPS-only with `__Host-` cookie; HTTP login is 400. `X-Forwarded-Proto` is not trusted unless `CLAIMFORGE_TEAM_TRUST_PROXY` is set. That flag is only safe when a trusted reverse proxy strips or overwrites client-supplied `X-Forwarded-Proto`.
18. A syntactically valid login slug does not reveal whether the tenant exists (same 302 as a live slug).
19. `team_oidc_pending` is bounded: consume deletes the row, expired rows are swept, and the table is capped (oldest evicted). Login remains not a slug oracle.

---

## 7. P1.2 OIDC and opaque sessions

Instance-wide confidential OIDC client. Endpoints and secrets are env-only (`CLAIMFORGE_TEAM_OIDC_*`, `CLAIMFORGE_TEAM_SEAL_KEY`). Missing issuer, endpoints, closed hostname allowlist, client secret, or seal key fail-closed (HTTP 503). Secrets live in a WeakMap on the frozen config object and must not appear in logs or `JSON.stringify`.

**Authorization Code + PKCE S256.** Static authorization/token/JWKS URLs (no discovery). State and nonce are CSPRNG. `team_oidc_pending` stores `state_hash`, nonce, code_challenge, AES-256-GCM `verifier_ciphertext`, redirect_uri, and `tenant_slug`. Consume is `DELETE ... RETURNING` (the used row does not remain). Expired rows are swept on insert/consume. The table is capped at 256 in-flight rows by evicting the oldest — so spam `GET /oidc/login?slug=` cannot grow it without bound, and valid slugs still all 302.

**JWKS / token fetch.** Reuse `inspectJwksUrl` / `fetchJwksDocument` with `teamMode: true` and a closed allowlist. Token POST and JWKS GET: `credentials:omit`, `redirect:manual` (3xx denied), timeout/content-type limits, body read from the stream via shared `readCappedBody` and aborted as soon as it exceeds the size cap (not `arrayBuffer()` then check). Audit `action` for the token POST is `token-exchange`, not `jwks-fetch`. No `createRemoteJWKSet`. Local verify via `createLocalJWKSet`; cache TTL 5 minutes; unknown `kid` refetches at most once. ID token algs: RS256 / PS256 / ES256 only; reject `none` and HS*. `iat` must not be more than 30s in the future and not older than 5 minutes (authorization-code freshness).

**Login bind.** `GET /api/team/oidc/login?slug=` requires HTTPS (request URL protocol; `X-Forwarded-Proto` is ignored unless `CLAIMFORGE_TEAM_TRUST_PROXY` is set — and that flag is only safe when a trusted reverse proxy strips or overwrites client-supplied `X-Forwarded-Proto`) and a **syntactically valid** slug. Login does **not** probe `team_tenant` — a live slug and an unknown valid slug both 302 to the IdP so existence is not an oracle. Callback verifies the ID token (exact `sub`, no trim), maps `iss`+`sub` to `user_key`, then `resolveTenantContextBySlug` — **no JIT** `team_member` insert. Unknown subject, unknown slug, or membership in a different tenant is 404.

**Opaque session.** `randomBytes(32)` base64url; DB stores SHA-256 only. `tenant_id NOT NULL` and `FOREIGN KEY (tenant_id, user_key) → team_member ON DELETE CASCADE`. TTL 12 hours from `created_at`; atomic `UPDATE token_hash` after 6 hours (previous hash stays valid for 60s so a concurrent request is not logged out; expiry is not extended). Revoke sets `revoked_at`. Cookie `__Host-claimforge-team.session`: Secure, HttpOnly, Path=/, SameSite=Strict, no Domain. HTTPS-only. Login/callback/logout/session responses set `Cache-Control: no-store` and `Pragma: no-cache`; callback also `Referrer-Policy: no-referrer`. `GET /api/team/session` returns `{userKey, tenantId}` — no tenant list, no role. Logout is local revoke only (`POST /api/team/oidc/logout`, same-origin).

**Client secrets:** stay in env. They are not written to Postgres.

---

## 8. Deferred (specified now, not built)

### Audit (P1.4)

Append-only `team_audit`. Who changed whose collab/membership/workspace. No capture bodies, no JWKS material. **IP and User-Agent are omitted** (ADR-023) — never raw IP and never `sha256(ip)`. Actor is the live session member. Tenant-scoped reads. Deleting a member does not erase rows. `GET /api/team/audit` is session-bound.

### RBAC HTTP (P1.3)

Role on the **member row** is authoritative. A JWT `role=admin` claim is not. Viewer cannot mutate. `accepted-risk` requires lead+. Admin+ may add/change/remove members; `owner` is bootstrap-only; the last owner cannot be removed or demoted. Members HTTP is session-bound (`GET/POST/PATCH/DELETE /api/team/members`). Server may refuse to persist loot/replay; it does not control in-browser copy.

Collab HTTP (policy/review/ReportDTO over HTTP) is P1.5; the kernel already applies RBAC and persist projection on `updateWorkspaceCollab`. Workspace list/create/delete HTTP is in the same slice because collab is per-workspace.

### Postgres RLS

PGLite tests prove application-level isolation and constraints. P1.7 (`migrations/0006_team_rls.sql`, ADR-040) adds `FORCE ROW LEVEL SECURITY` on member/workspace/collab/audit keyed by `claimforge.tenant_id`. The kernel `SET LOCAL`s that GUC from the WeakMap snapshot in the same transaction. PGLite accepts the DDL but does not enforce it. The claim is the dedicated Postgres integration test (`p1-7-rls.test.ts`) against a non-superuser role. Lookup tables (`team_tenant`, `team_oidc_pending`, `team_session`) are not RLS'd. This is not cryptographic isolation: a stolen app role that knows a tenant UUID can still `SET` the GUC.

### CI vs merge policy

GitHub Actions `ci` / `gates` currently runs on `push` to `main` and on `pull_request`. **`main` has no branch protection / ruleset** at the time of this spec. Passing CI is evidence the HEAD was green; it is **not** merge-enforced until a ruleset requires the `ci` / `gates` check. Do not describe CI as a merge gate before that.

---

## 9. P1.1 deliverable

- This document + ADRs in `docs/agent/DECISIONS.md`
- Migration `0003_team_isolation.sql`
- Pure repository layer `src/lib/team/*` (kernel: no HTTP, no UI)
- Adversarial tests + `p1-gates.ts`
- Solo/Lab regression tests

P1.1 out of scope (now P1.2 or later): OIDC routes, session cookies, RBAC middleware, Team UI, audit table, capture upload.

## 10. P1.2 deliverable

- ADR-034 + threat-model P1.2 section
- Migration `0004_team_oidc_sessions.sql` (additive; does not rewrite 0003)
- TeamSql transactions on one Neon connection (`wrapPgPool` / SAVEPOINT)
- Env OIDC loader, PKCE S256, sealed `code_verifier`, outbound SSRF gate, local JWKS verify
- Routes: `GET /api/team/oidc/login?slug=`, `GET /api/team/oidc/callback`, `POST /api/team/oidc/logout`, `GET /api/team/session`
- Operator CLI `npm run team:bootstrap` (env secret, `DATABASE_URL`, no HTTP, no PGLite fallback)
- Opaque tenant-bound sessions + `__Host-claimforge-team.session`
- P1.2 gates in `p1-gates.ts` and adversarial tests

Out of scope: P1.4 audit, P1.5 collab HTTP, P1.6 UI, tenant listing, IdP logout, OIDC discovery, JIT provisioning.

## 11. P1.3 deliverable

- ADR-036
- Live `team_member.role` capability checks in the kernel (`rbac.ts`)
- `GET/POST/PATCH/DELETE /api/team/members` (session-bound; no tenant_id; no JWT role)
- Viewer read-only; `accepted-risk` lead+; admin+ member management; last owner protected
- P1.3 gates in `p1-gates.ts` and `p1-3-rbac.test.ts` / `p1-3-http.test.ts`

Out of scope for that slice: P1.4 audit, P1.5 collab HTTP, P1.6 UI.

## 12. P1.4 deliverable

- ADR-037 + ADR-023 omit-IP lock
- Migration `0005_team_audit.sql` (additive; UPDATE trigger; no member FK; no IP/UA columns)
- Kernel append on member/workspace/collab mutations in the same transaction
- `GET /api/team/audit` (session-bound; no tenant_id; no actor override)
- P1.4 gates in `p1-gates.ts` and `p1-4-audit.test.ts` / `p1-4-http.test.ts`

Out of scope: P1.5 collab HTTP, P1.6 UI, HMAC-IP, tenant listing.

## 13. P1.5 deliverable

- ADR-038
- Session-bound `GET/POST/DELETE /api/team/workspaces` and `GET/PATCH /api/team/collab`
- Persist allowlist and RBAC stay in the kernel (`assertAllowedCollab`, live `team_member.role`)
- Viewer GET; analyst+ writes; `accepted-risk` lead+; missing/cross-tenant 404; caller `tenant_id` 400
- P1.5 gates in `p1-gates.ts` and `p1-5-http.test.ts`

Out of scope: P1.6 Team UI, HMAC-IP, tenant listing, capture upload.

## 14. P1.6 deliverable

- ADR-039
- More → Team inspect view (not a primary tab)
- Slug sign-in, session, members, workspaces, push/pull collab, audit
- Role from members list; no tenant list; loot/replay copy documented as local
- P1.6 gates in `p1-gates.ts` and `p1-6-ui.test.ts`

Out of scope: tenant listing, HMAC-IP, capture upload, IdP logout, OIDC discovery.

## 15. P1.7 deliverable

- ADR-040
- Migration `0006_team_rls.sql` (additive FORCE RLS)
- Kernel `SET LOCAL claimforge.tenant_id` in `withActiveMember`
- Dedicated Postgres integration test (non-superuser, missing GUC hides rows)
- CI Postgres service + `CLAIMFORGE_TEAM_RLS_DATABASE_URL`

Out of scope: tenant listing, HMAC-IP, capture upload, IdP logout, OIDC discovery, JIT.


