## 2026-08-30 — P1.1 post-mint authority + Team projection

- Independent review reproduced cross-tenant list/get/collab/addMember/delete by mutating `TenantContext.tenantId` or copying the brand symbol on `f3f7878`.
- Context mint now registers a frozen snapshot in a module-private WeakMap. Repo SQL uses `requireActiveMember` (snapshot + live `team_member` SELECT), never `ctx.tenantId`.
- Persist is a Team projection: `loot.value` and `replays.raw`/`curl` always `[redacted]`; canaries remain defense-in-depth. No HTTP/OIDC/P1.2.

## 2026-08-30 — P1.1 persist/context hardening

- Removed public `contextFromMember`. Brand is stamped only inside bootstrap (after insert) and resolve (after SELECT). Member objects are not context.
- ReportDTO persist is a strict schema (unknown fields rejected), then deep-redacted into a new object, then UTF-8/element capped. Same sanitizer on read.
- Collab write is `INSERT ON CONFLICT DO UPDATE`. Adversarial: api_key, sessionSecret, HTTP under innocuous names, nested unknown fields, oversize Base64, tampered row, concurrent first-write.
- Scope still P1.1: no HTTP/OIDC/UI/RBAC.

## 2026-08-30 — P1.1 tenant isolation kernel

- Branch `feat/p1-isolation-kernel`. Docs commit already on the branch; this slice is the kernel only.
- Migration `0003_team_isolation.sql`: tenant / member / workspace / collab with composite PK/FK. No session, OIDC, or audit tables.
- Repo is pure (no HTTP/UI). Every query takes branded `TenantContext` and scopes `tenant_id = ctx.tenantId`. Bootstrap requires `unlockBootstrap` (timing-safe, secret ≥ 16).
- Persist allowlist: policy, review, deep-redacted ReportDTO. Compact JWT / live Bearer / HAR / aRaw rejected. Engine `toReportDTO` is persistable (`Bearer [redacted]` is not treated as a live token).
- Adversarial tests: forged context, caller tenantId, cross-tenant CRUD, composite FK, same user two tenants, fail-closed leak, migration rollback, solo/lab untouched, no platform-auth import.
- Gates: typecheck, lint, `npm test` 408/404 pass/4 skip, audit 0 high, production build. Skip count still 4.
- Not started: P1.2 OIDC/sessions. CI is not merge-enforced.

## 2026-08-30 — P1.0 Team isolation architecture

- Confirmed main HEAD `f1ed912`; CI run 20 green (387 tests, 383 pass, 4 skip).
- Accepted: Team OIDC ≠ Grok Better Auth; `VITE_AUTH_ENABLED=false`; no `authMiddleware`/`requireUserId` on Team.
- Accepted: P1 does not persist raw HAR/HTTP/JWT/cookie/credentials.
- Wrote `docs/P1_TEAM_ISOLATION.md` and ADR-017–031. P1.1 kernel follows on `feat/p1-isolation-kernel`. No P1.2.

## 2026-08-30 — Remainder P0 + CI gates (repair)

- Recorded true HEAD `4fdf31b` first: previous remainder snapshot claimed 387/0 and remainder SHA `2876097`; GitHub Actions run 18 on that HEAD was **379 pass / 8 fail**.
- Remainder P0 already landed in `2876097` vs `8740c6f`: regex Apply block, role-hierarchy scoring, JWKS closed allowlist, paginated PDF. Tightened: `policyApplyDecision` refuses Apply, ROLE_ESCALATION capped at High, PDF adds How + page numbers.
- CI `npm test` failed because `.grok/` and `AGENTS.md` are gitignored. Sandbox-doc tripwires skip when those files are absent. Workflow materializes auth-off `.grok/app-env.json` so first-party tests and production build agree.
- Local: 387 pass. GitHub-checkout sim: 383 pass / 4 skip / 0 fail. typecheck, lint, audit:deps (0 high), build green.
- Do not start P1 Team.

## 2026-08-30 — Remainder P0 + CI gates

- Policy Apply validates regex and surfaces field errors; invalid patterns do not re-run.
- Role hierarchy scores: JWT priv-role only for tree parents; user→admin mass-assign is Confirmed ROLE_ESCALATION (not Critical). Empty tree never escalates.
- JWKS allowlist is a closed exact-hostname set in every mode; teamMode still blocks RFC1918/ULA; every redirect hop rechecked.
- PDF paginates with kill chain, findings, why, evidence, loot.
- CI: typecheck, lint, `npm test` (all first-party), `audit:deps`, production build.
- Browser: invalid `(unclosed` blocked; hierarchy Apply changed mass-assign observation/high → confirmed/high; Export PDF no console errors.
- 387 first-party tests green. Do not start P1 Team.

## 2026-08-30 — P0.1 policy editor (remainder)

- More → Policy: routes, ownership fields, statuses, JWT iss/aud, logout, role hierarchy.
- Apply re-runs the same engine and lists added/removed/changed findings. Version bumps on content change.
- Extra ownership fields (tenantId) work. Public/shared classification uses policy, not a hardcoded regex.
- 151 tests green. Browser: invoices-as-public demotes lab BOLA.

## 2026-08-30 — P0.8 adversarial fail-then-pass gates

- Catalog `p0-gates.ts` maps every P0.1–P0.7 bug to a test that would fail if the fix is reverted.
- New gaps: path-as-owner, wordlist formula injection, JWKS credentials=omit, audit without JWK n/e, CORS *+credentials through analyze.
- 143 tests green. P0 slices complete. Do not start Team unless asked.

## 2026-08-30 — P0.7 confidence / severity / review state

- Every finding family now has deterministic reason codes, Observation/Suspicion/Confirmed, and an analyst review state.
- Critical requires proven impact (trusted ownership + cross-actor 2xx). JWT alg=none and cookie flags cannot be Confirmed/Critical.
- Analyst review overlays persist by fingerprint; engine confidence is immutable.
- 134 tests green. Next: P0.8 adversarial-gate completeness.

## 2026-08-30 — P0.6 JWKS network guards

- HTTPS-only except localhost HTTP. Confirm dialog. Timeout 8s, 64KiB, JSON content-type, redirect revalidation.
- Metadata/userinfo blocked. Team mode RFC1918 + allowlist.
- 125 tests green. Next: P0.7 review/confidence.

## 2026-08-30 — P0.5 forge revision machine

- Unsigned draft / Signed output / Stale output.
- Changing header/payload/alg/HMAC/PEM/JWKS/kid/iss/aud voids signed copy.
- 117 tests green. Next: P0.6 JWKS network.

## 2026-08-30 — P0.4 session/logout credential scope

- Logout revokes only credentials on that request.
- 105 tests green. Next: P0.5 forge revision machine.

## 2026-08-30 — P0.3 replay credential boundary

- Source credentials wiped, selected actor set attached.
- 101 tests green. Next: P0.4 logout/session.

## 2026-08-30 — P0.2 ReportDTO

- Allowlist ReportDTO; canaries.
- Next: P0.3 replay credentials.

## 2026-08-30 — P0.1 trust boundary + agent docs bootstrap

- Policy/evidence/hash/versions. docs/agent bootstrap.
- Next: P0.2 ReportDTO.
