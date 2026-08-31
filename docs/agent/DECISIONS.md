# Decisions

## ADR-001 — Analyst labels are trusted identity in Solo mode

Unsigned/unverified JWTs are common in lab HAR. Spec allows analyst-declared actor mapping as a trusted identity source. Default policy therefore treats `aLabel`/`bLabel` as trusted owner names when matching response `ownerId`/`userId`. Unverified JWT `sub` is never trusted.

## ADR-002 — Request body is never ownership proof

`ownerLinks` on `requestBody` (and query/path) cannot populate `ownedObjects`. Only response JSON owner fields (allowlisted) and inventory arrays on identity/private routes.

## ADR-003 — JWT subject values are never object ids

Inventory and owner-object ids that equal any captured JWT subject (even unverified) are skipped so `sub`/`userId` colliding with `/resource/{id}` cannot confirm BOLA.

## ADR-004 — Exporters only accept ReportDTO

`exportReportJson` / markdown / html / pdf map from `toReportDTO`. Diff samples, jwt payload, cookie values, and raw HAR are dropped rather than redacted-in-place.

## ADR-005 — PDF is a generated text PDF

No PDF library in the tree. P0.2 ships a PDF 1.4 Helvetica renderer for canaries and offline share. Remainder paginates (~46 lines/page) and includes kill chain, findings, why, reason codes, evidence, and loot. Layout quality remains P3.

## ADR-006 — Replay wipes source credentials then attaches one actor set

P0.3 strips credential-class headers then attaches only the selected actor set.

## ADR-007 — Logout revokes only credentials on that request

Each bearer, session cookie, and API-key is its own session. Sibling devices stay live.

## ADR-008 — Forge signed output is revision-bound

A signed compact JWT is valid to copy only while `signedAtRevision === revision`.

## ADR-009 — JWKS fetch is confirmed, allowlisted, and never uses createRemoteJWKSet

P0.6 fetches the JWKS document with `credentials:omit`, `redirect:manual`, HTTPS (HTTP loopback only), size/timeout/content-type gates, and `jwksConfirmed`. Audit stores hostname/status/bytes, never tokens or JWK material. A non-empty hostname allowlist is a closed exact-hostname set in every mode. Team mode additionally blocks private/link-local/metadata.

## ADR-010 — Engine confidence is not analyst review

P0.7 keeps two orthogonal fields on every finding:

- `confidence` (Observation / Suspicion / Confirmed) is deterministic, produced by the rule engine, and cannot be edited.
- `reviewState` is the analyst workflow (`new` → `needs-evidence` | `confirmed` | `rejected` | `accepted-risk` → `fixed` → retest).

Severity never becomes Critical from a finding type name. Observation and Suspicion cap at High. Confirmed Critical requires proven impact (`CROSS_ACTOR_2XX` + `SERVER_OWNERSHIP_PROOF`). Analyst review overlays persist by fingerprint and survive re-analysis without changing engine confidence.

## ADR-011 — P0.8 is a fail-then-pass catalog, not a rewrite

Each P0.1–P0.7 bug is a row in `p0-gates.ts` with `before` (broken engine) and `after` (required behavior), pointing at a test that would fail if the fix is reverted. New gaps (path-as-owner, wordlist formulas, JWKS `credentials:omit`, audit JWK material, CORS `*`+credentials through analyze) live in `p0-adversarial-gate.test.ts`. Remainder rows cover invalid regex, role-hierarchy scoring, allowlist closed set, and PDF pagination.

## ADR-012 — Policy editor re-runs one engine, does not rewrite the desk

P0.1 remainder is a More-view editor. Public/shared/private/identity patterns, ownership fields, success/deny statuses, JWT iss/aud, logout paths, role hierarchy, and JWKS allowlist all feed the same `AnalysisPolicy`. Apply bumps version when content changes, re-runs analyze, and diffs findings by fingerprint (added / removed / changed). Extra ownership field names (e.g. `tenantId`) are allowed; request body/query/path still cannot prove ownership. Invalid regex is reported and blocks Apply. No Team backend. Primary tabs unchanged.

## ADR-013 — Role hierarchy scores only when declared

Empty `roleHierarchy` never escalates (demo mass-assign stays Observation). When a tree is declared: JWT privileged-role findings fire only for tree parents; a mass-assign that writes a strictly superior role is Confirmed `ROLE_ESCALATION`, severity capped below Critical (no cross-actor ownership proof).

## ADR-014 — JWKS allowlist is a closed set in every mode

A non-empty `jwksHostnameAllowlist` is exact-hostname match (trailing-dot normalized, no subdomain inheritance) for every hop, including solo. Empty list stays open in solo. Team mode still blocks RFC1918 / ULA / link-local / metadata even if listed; loopback in team mode requires allowlist membership. Fetch stays `credentials:omit` + `redirect:manual`.

## ADR-015 — CI required gates are typecheck, lint, all first-party tests, audit, build

`.github/workflows/ci.yml` runs `npm run typecheck`, `lint`, `npm test` (quoted `src/**/*.test.ts` + `scripts/*.test.mjs`), `npm run audit:deps` (`npm audit --audit-level=high`), and `npm run build`. Platform chrome unit tests isolate from product `site.json` / `public/og.jpg`. Auth migration glob must not include `migrations/auth/0001_auth.sql`; product SQL in `migrations/` is allowed. Sandbox-only tripwires that read gitignored `AGENTS.md` / `.grok/skills` skip when those files are absent. CI materializes `.grok/app-env.json` (`VITE_AUTH_ENABLED=false`) because `.grok/` is gitignored and ClaimForge is auth-off.

Passing those jobs on a SHA is evidence that HEAD was green. It is **not** a GitHub merge requirement until a ruleset/branch-protection rule requires `ci` / `gates`. See ADR-029.

## ADR-016 — Agent docs record git HEAD, not a sibling remainder SHA

`HANDOFF.md` and `TEST_STATUS.md` must name `git rev-parse HEAD` and the working tree (including untracked files). A feature parent may be listed separately. Claiming tests green requires the GitHub Actions run on that HEAD, not only a local `npm test`. Do not add a follow-up commit whose only purpose is to make these files echo their own SHA.

## ADR-017 — Solo remains default; Team is opt-in self-hosted

The browser desk and in-browser engine stay the product default. Team features require an operator-run database and (from P1.2) a customer IdP. Absence of Team config must not change Solo behavior, localStorage persistence, or the victim lab.

## ADR-018 — Team identity is not Grok Better Auth

`VITE_AUTH_ENABLED` stays `"false"`. Do not copy `migrations/auth/0001_auth.sql` into `migrations/`. Team modules must not import `authMiddleware`, `requireUserId`, or `@/lib/auth/server`. Platform `requireUserId` fail-closes when `DATABASE_URL` is set and auth is off; using it for Team would 500 every request. Customer OIDC is a separate plane (`src/lib/team`), not the Grok broker.

## ADR-019 — TenantContext comes only from a verified membership or bootstrap row

`tenant_id` is never read from body, query, arbitrary headers, or unlinked JWT claims. Repository functions accept a branded, frozen `TenantContext` registered in a module-private WeakMap at mint (bootstrap insert or membership SELECT only). SQL authority is the frozen snapshot plus a live `team_member` SELECT (`requireActiveMember`), never `ctx.tenantId` / `ctx.userKey` / `ctx.role`. There is no public `contextFromMember`. Symbol copies and post-mint mutation cannot retarget a tenant.

## ADR-020 — Team persist allowlist is policy, review, projected ReportDTO

No raw HAR, raw HTTP, JWT compact tokens, cookie values, or credentials on the Team server. Collab writes run `assertAllowedCollab`: strict ReportDTO schema (reject unknown fields), server-side **Team projection** (`loot.value` and `replays.raw`/`curl` always `[redacted]`), re-parse as Team schema, deep-redact into a new object, UTF-8/element caps, then canary scan. Reads re-parse stored JSON as the Team schema. Capture sharing is a later phase after threat-model + encryption work.

## ADR-021 — OIDC client secrets are never plaintext in the database

P1.1 stores no OIDC secrets. Future IdP `client_secret` values go to a secret manager or envelope encryption with a server-managed key (env/KMS). Spec: `docs/P1_TEAM_ISOLATION.md`.

## ADR-022 — RBAC is P1.3; isolation does not wait for it

P1.1 prevents cross-tenant access regardless of role. Role enum exists on `team_member` for the kernel graph; HTTP enforcement and privilege tests are P1.3. JWT `role` claims are not trusted.

## ADR-023 — Audit must not store raw or unsalted IP hashes

Deferred to P1.4. If IP is logged at all, use HMAC with a rotating server key, never `sha256(ip)` and never raw IP. P1.1 has no audit table.

## ADR-024 — Future sessions are opaque tokens stored as hashes

P1.2: cryptographic random token, DB stores hash only, with expiry, rotation, and revoke. Cookie may carry the raw token (`__Host-claimforge-team.session`). No session table in P1.1.

## ADR-025 — Product SQL is globbed; auth SQL is not

Team tables live in `migrations/0003_team_isolation.sql`. `migrations/auth/` stays out of both appliers until sign-in is explicitly turned on (it will not be for Team).

## ADR-026 — First tenant and first owner are an operator bootstrap

`unlockBootstrap` + `bootstrapTenant` in one transaction. No public endpoint may self-assign `owner`. Empty configured secret disables bootstrap. P1.2 ships the operator CLI in ADR-035.

## ADR-027 — Server authorization cannot claim to control in-browser export

Loot, replay curl, and raw capture strings that exist only in the tab are local analyst actions. Team RBAC may refuse to persist or return them; it must not be described as preventing browser-side copy.

## ADR-028 — PGLite proves the kernel; Postgres RLS is defense-in-depth

P1.1 adversarial tests run against PGLite (transactional DDL, constraints, repo scoping). Row Level Security on Neon/Postgres is not claimed until a dedicated integration test exists.

## ADR-029 — CI green is not a merge gate until a ruleset exists

`main` currently has no branch protection. Workflow `ci` / job `gates` running successfully on a SHA is evidence, not merge-enforcement. Do not call CI “required to merge” until a ruleset requires that check.

## ADR-030 — Same-tenant graph is enforced with composite keys

`team_member`, `team_workspace`, and `team_workspace_collab` use composite primary keys including `tenant_id`. Child FKs are `(tenant_id, workspace_id)` and `(tenant_id, user_key)` so a row cannot reference another tenant’s workspace or member.

## ADR-031 — P1.1 ships no HTTP, UI, session, or OIDC

The isolation kernel is a repository + migration + tests. Expanding to P1.2 without an explicit request is out of scope.

## ADR-032 — Collab persist is projection + canary + upsert

P1.1 persist is not a key-name heuristic and is not “regex means no credentials.” Incoming ReportDTO is a closed shape. The stored object is a newly allocated Team projection (`loot.value` / `replays.raw` / `replays.curl` = `[redacted]`), then deep-redacted, then canary-scanned. `team_workspace_collab` writes use `INSERT ON CONFLICT DO UPDATE` so concurrent first-writes merge columns instead of racing SELECT+INSERT.

## ADR-033 — TenantContext identity is WeakMap + freeze + live membership

Brand symbols are defense-in-depth. Authority is `WeakMap` object identity: mint after SQL, freeze context and snapshot, re-SELECT membership on every public repo call. A deleted member cannot keep using a previously minted context. Bootstrap actors use the same registry pattern.

## ADR-034 — P1.2 is instance-wide OIDC with opaque tenant-bound sessions

Locked for the P1.2 epic:

- One IdP per ClaimForge instance, env-configured (`CLAIMFORGE_TEAM_OIDC_*`). Confidential client; `client_secret` and `CLAIMFORGE_TEAM_SEAL_KEY` never enter Postgres, logs, or JSON serialization (WeakMap).
- Authorization Code + PKCE S256. Static authorization/token/JWKS endpoints (no discovery). Closed hostname allowlist is mandatory. Fail-closed if issuer, endpoints, allowlist, secret, or seal key is missing.
- JWKS: reuse P0.6 SSRF gate (`teamMode`, `credentials:omit`, `redirect:manual`). `createLocalJWKSet` only — never `createRemoteJWKSet`. Cache with TTL; unknown `kid` refetches at most once.
- ID token: RS256/PS256/ES256; reject `none` and HS*; verify sig/iss/aud/azp/exp/iat/nonce. `iat` may be at most 30s in the future and at most 5 minutes old (code-exchange freshness). `sub` is the exact OIDC subject (no trim).
- `user_key = "oidc:" + sha256(JSON.stringify([iss, sub]))`. Login requires a syntactically valid `?slug=`; it does not probe tenant existence (no 302/404 oracle). Tenant/membership fail-closed at callback. No JIT `team_member`. JWT `tenant_id`/`role` are not trusted.
- Sessions: CSPRNG 32-byte token, SHA-256 in `team_session`, `tenant_id NOT NULL`, FK to `team_member ON DELETE CASCADE`. TTL 12h from `created_at`; atomic rotate after 6h with 60s previous-token grace so concurrent requests are not logged out. Cookie `__Host-claimforge-team.session` Secure+HttpOnly+Path=/+SameSite=Strict, no Domain. HTTPS is the request URL protocol; `X-Forwarded-Proto` is ignored unless `CLAIMFORGE_TEAM_TRUST_PROXY` is set. That flag is only safe when a trusted reverse proxy strips or overwrites client-supplied `X-Forwarded-Proto`.
- `code_verifier` is AES-256-GCM sealed with a key derived from `CLAIMFORGE_TEAM_SEAL_KEY`. State stored as hash. Consume is `DELETE ... RETURNING`. Expired pending rows are swept. In-flight pending is capped at 256 (oldest evicted) so login spam cannot grow the table; valid slugs still all 302.
- Token POST and JWKS GET bodies are read from the stream and aborted at the size cap (`readCappedBody`). Token audit action is `token-exchange`.
- Auth HTTP responses set `Cache-Control: no-store` (and `Pragma: no-cache`); callback sets `Referrer-Policy: no-referrer`.
- Neon `TeamSql.transaction` checks out **one** connection for BEGIN/queries/COMMIT (SAVEPOINTs for nesting). No pooled BEGIN/COMMIT.
- Logout is local revoke only. No tenant list in P1.2. Not Grok Better Auth.

Supersedes the “future” wording in ADR-024 for the P1.2 slice; P1.1 still has no session table of its own.

## ADR-035 — First OIDC tenant is bootstrapped by an operator CLI

P1.2-R3:

- No HTTP bootstrap route. Operators run `npm run team:bootstrap`.
- `DATABASE_URL` is required. The CLI must not fall back to the preview PGLite database.
- `CLAIMFORGE_TEAM_BOOTSTRAP_SECRET` is read from the environment only (length ≥ 16). `--secret` / token-like flags are rejected.
- CLI flags are `--slug`, `--name`, `--issuer`, `--sub`. `user_key = oidcUserKey(issuer, sub)` (exact `sub`, no trim).
- The process calls `unlockBootstrap` + `bootstrapTenant` inside the existing TeamSql transaction helper (`wrapPgPool` on a checked-out Postgres connection).
- Stdout is JSON `{tenantId, slug, userKey}` only. Stderr messages are generic Team errors. Never log the bootstrap secret, client secret, tokens, or raw `sub`.
- Fail-closed on missing input/env, missing `team_tenant`/`team_member`, or duplicate slug.
- Procedure: `docs/operator/BOOTSTRAP.md`. Still no JIT, no Better Auth, no P1.3.

