## 2026-09-01 — A-lab reconfirm recorded on main

- User pick **2 = ghi A-lab lên main** after a new-chat Lab A run. Docs only. Product still `9cbd88d`. Lab script stays untracked.
- Chromium cookie jar + real Postgres 16: **31/31 pass** (session omits role; `__Host-` cookie; Bearer JWT 401; HTTP 400; `token_hash` is SHA-256; audit omits tenantId/IP; viewer/analyst/lead RBAC; cross-tenant 404; capture rejected; loot/replay projected; admin cannot assign owner; last owner stays; member delete keeps audit; `team_audit` UPDATE rejected; missing GUC hides workspaces; SET LOCAL lists session tenant; FORCE RLS on member/workspace/collab/audit; More → Team inspect).
- Firefox skipped (no browser binary). Counted as skip, not a product fail. Did not start capture-share.
- Next agent: clone GitHub, checkout `main`, read `docs/agent/HANDOFF.md`. Do not scaffold. Do not re-implement P1.4–P1.7. Do not merge unless they pick merge.

## 2026-09-01 — handoff to new chat

- User asked to bàn giao for a new chat. No product change. Lab script stays untracked.
- Live product on `main`: P1.7 squash `9cbd88d` (PR #7). A-lab 31/31 recorded.
- Next agent: clone GitHub, checkout `main`, read `docs/agent/HANDOFF.md`. Do not scaffold. Do not re-implement P1.4–P1.7. Do not merge unless they pick merge. Vietnamese + product terms. End every turn with a picker. Default keep-`main`.

## 2026-09-01 — A-lab P1.4–P1.7 (sandbox-only)


- User pick **2 = Lab A Team** after P1.7 merge. Did not start capture-share. Lab script is untracked (not committed).
- Chromium cookie jar + real Postgres 16: **31/31 pass** (session omits role; Bearer JWT 401; HTTP 400; `token_hash` is SHA-256; audit omits tenantId/IP; viewer/analyst/lead RBAC; cross-tenant 404; capture rejected; loot/replay projected; admin cannot assign owner; last owner stays; member delete keeps audit; `team_audit` UPDATE rejected; missing GUC hides workspaces; SET LOCAL lists session tenant; FORCE RLS on member/workspace/collab/audit; More → Team inspect).
- Firefox did not launch (missing GTK). Counted as skip, not a product fail.
- Next agent: clone GitHub, checkout `main`, read this HANDOFF. Do not scaffold. Do not re-implement P1.4–P1.7.

## 2026-09-01 — P1.7 merged to main


- User pick **2 = merge P1.7**. Squash PR [#7](https://github.com/ThienPhuc-2005/ClaimForge/pull/7) → `9cbd88d`.
- CI on merge: [run 33509604074](https://github.com/ThienPhuc-2005/ClaimForge/actions/runs/33509604074) success (evidence, not a merge gate).
- Did not start capture-share, JIT, tenant listing, HMAC-IP, IdP logout, or OIDC discovery.
- Next agent: clone GitHub, checkout `main`, read this HANDOFF. Do not scaffold. Do not re-implement P1.4–P1.7.

## 2026-09-01 — P1.7 Postgres RLS in progress


- User asked to do remaining work. Did **not** start capture-share, JIT, tenant listing, HMAC-IP, or IdP logout (those stay out of scope / need a new threat model).
- Slice: P1.7 `feat/p1.7-rls` — additive `0006_team_rls.sql`, kernel `SET LOCAL claimforge.tenant_id`, Postgres integration test (non-superuser). ADR-040.
- Local tests: **512 pass / 0 fail** with `CLAIMFORGE_TEAM_RLS_DATABASE_URL`. Draft PR next; do not merge unless asked.

## 2026-09-01 — A-lab P1.4–P1.6 (sandbox-only)

- User pick **2 = Lab A Team** (typed `22`). Did not start capture-share. No product commit.
- Chromium cookie jar + real Postgres 16: **27/27 pass** (session omits role; Bearer JWT 401; HTTP 400; `token_hash` is SHA-256; audit omits tenantId/IP; viewer/analyst/lead RBAC on collab; cross-tenant 404; capture rejected; loot/replay projected; admin cannot assign owner; last owner stays; member delete keeps audit; `team_audit` UPDATE rejected; More → Team inspect).
- Firefox did not launch in this sandbox (missing GTK). Counted as skip, not a product fail.
- Next agent: clone GitHub, checkout `main`, read this HANDOFF. Do not scaffold. Do not re-implement P1.4–P1.6.

## 2026-09-01 — hold main after P1.4–P1.6 merge

- User pick **1 = giữ `main`**. Did not start A-lab. Did not start capture-share. No product commit after squash `1be6d07`.
- Live handoff is `main` (product `1be6d07`, docs `f4c629e`).
- Next agent: clone GitHub, checkout `main`, read this HANDOFF. Do not scaffold. Do not re-implement P1.4–P1.6. Do not start lab or capture-share unless the user picks it.

## 2026-09-01 — P1.4–P1.6 merged to main

- User pick **2 = merge**. Squash-merged [PR #6](https://github.com/ThienPhuc-2005/ClaimForge/pull/6) as `1be6d07` (`feat(p1.4-p1.6): audit, collab HTTP, and More Team inspect view (#6)`).
- [#4](https://github.com/ThienPhuc-2005/ClaimForge/pull/4) and [#5](https://github.com/ThienPhuc-2005/ClaimForge/pull/5) closed as superseded (same stack). Did not merge them separately.
- CI on `main` [run 41](https://github.com/ThienPhuc-2005/ClaimForge/actions/runs/33500312474) green. Not a merge gate (ADR-029).
- Did not start capture-share. Did not run an A-lab for P1.4–P1.6.
- Next agent: clone GitHub, checkout `main`, read this HANDOFF. Do not scaffold. Do not re-implement P1.4–P1.6.

## 2026-09-01 — handoff for a new chat (drafts held)

- User pick **1 = giữ PR nháp**. Did not merge #4/#5/#6. Did not start capture-share.
- Live handoff is this branch `feat/p1.6-team-ui` (not `main` `944f81b`, which still says P1.4 not started).
- Stack: P1.4 `83059bb` PR #4 CI run 36; P1.5 `9e3c4ee` PR #5 CI run 37; P1.6 `914eb27` PR #6 CI run 39. All draft, all green.
- Next agent: clone GitHub, checkout `feat/p1.6-team-ui`, read this HANDOFF. Do not scaffold. Do not re-implement P1.4–P1.6. Merge only if the user picks merge.

## 2026-09-01 — P1.6 Team UI started

- Branch `feat/p1.6-team-ui` from `feat/p1.5-collab-http` `9e3c4ee` (PR #5 still draft). Draft only. Do not merge P1.6 from this session.
- More → Team inspect view. Slug sign-in, members, workspaces, push/pull collab, audit. ADR-039.
- Role from members list. No tenant list. Loot/replay copy documented as local (ADR-027). Callback opens `/?team=1`.
- Local gates: typecheck, lint, `npm test` 509 / 505 pass / 4 skip / 0 fail, audit 0 high, build pass.
- Draft [PR #6](https://github.com/ThienPhuc-2005/ClaimForge/pull/6). CI run 39 green. Do not start capture-share unless asked.

## 2026-09-01 — P1.5 collab HTTP started

- Branch `feat/p1.5-collab-http` from `feat/p1.4-audit` `83059bb` (PR #4 still draft). Draft only. Do not merge P1.5 from this session.
- Session-bound `GET/POST/DELETE /api/team/workspaces` and `GET/PATCH /api/team/collab`. Kernel persist + live-role RBAC. ADR-038.
- Viewer GET; analyst+ writes; accepted-risk lead+; cross-tenant 404; no tenant_id; loot/replay projected.
- Next: wait for CI on the draft PR. P1.6 only if asked.

## 2026-09-01 — P1.4 append-only audit started

- Branch `feat/p1.4-audit` from `origin/main` `944f81b`. Draft only. Do not merge P1.4 from this session.
- Additive `0005_team_audit.sql`: no IP/UA columns, no member FK, UPDATE rejected.
- Kernel logs member/workspace/collab mutations in the same transaction. Actor is live `team_member.role`.
- `GET /api/team/audit` session-bound. Closed detail shapes; no capture/JWKS. ADR-037.
- Next: wait for CI on the draft PR. P1.5 only if asked.

## 2026-09-01 — P1.3 merged; A3 lab; handoff

- Squash-merged PR #3 into `main` as `4cefe02`. CI run 34 green.
- P1.3-A3 lab 36/36: Chromium + Firefox + real Postgres. Cookie not JWT; session omits role; viewer/analyst cannot escalate; admin cannot assign owner. No commit from the lab (local vite TLS patch restored).
- Docs handoff for a new implementing session. P1.4 not started.

## 2026-09-01 — P1.3-R1 extra RBAC HTTP cases


- Extra tests: analyst/lead cannot escalate via members HTTP; viewer GET 200; session JSON still omits role; Bearer JWT is 401; HTTP URL is 400; unknown delete 404; invalid role 400; viewer still reads workspace/collab.
- CI run 32 on `3c8201b` was already green; this is additional coverage. Draft kept. Do not merge.

## 2026-09-01 — P1.2 merged; P1.3 RBAC HTTP started


- Squash-merged PR #2 into `main` as `6de17a4` after A1 20/20 and A2 26/26 (Chromium + Firefox cookie jars, PostgreSQL `token_hash` only, membership CASCADE).
- Started `feat/p1.3-rbac-http`: live member-row RBAC, members HTTP, ADR-036. Draft only. Do not merge P1.3 from this session.

## 2026-08-31 — P1.2-R3-R1 operator CLI completion semantics


- `close()` after a committed bootstrap no longer flips the process to failure or mixes JSON + stderr. Failed bootstrap + failed close keeps the original safe error.
- Entry uses `process.exitCode` instead of `process.exit(code)` so stdio can flush.
- Draft PR #2 kept. Did not merge. Did not start P1.3.

## 2026-08-31 — P1.2-R3 operator bootstrap CLI

- Operator-only `npm run team:bootstrap`: `--slug --name --issuer --sub`. Secret from `CLAIMFORGE_TEAM_BOOTSTRAP_SECRET`. Requires `DATABASE_URL` (no PGLite fallback, no HTTP).
- `oidcUserKey` + `unlockBootstrap` + `bootstrapTenant` on wrapPgPool. Stdout is tenant id, slug, derived user_key. Fail-closed on missing env, unmigrated schema, duplicate slug.
- Docs: `docs/operator/BOOTSTRAP.md`, ADR-035. Draft PR #2 kept. Did not merge. Did not start P1.3.

## 2026-08-30 — P1.2-R2 pending bound + stream-capped JWKS

- Consume pending with `DELETE ... RETURNING`; sweep expired; cap 256 by evicting oldest. Login spam is not a slug oracle. Replay still 401.
- Shared `readCappedBody` stream-caps JWKS GET and token POST (cancel at size cap; no `arrayBuffer` then check).
- `CLAIMFORGE_TEAM_TRUST_PROXY` is only safe when a trusted reverse proxy strips or overwrites client `X-Forwarded-Proto`.
- Draft PR #2 kept. Did not merge. Did not start P1.3.

## 2026-08-30 — P1.2-R1 review blockers

- Stream-capped token POST body (no `arrayBuffer` then size check). Audit action `token-exchange`.
- `X-Forwarded-Proto` ignored unless `CLAIMFORGE_TEAM_TRUST_PROXY`. Login slug is not a tenant-existence oracle.
- Exact OIDC `sub` (no trim). ID token `iat` future/stale window. `Cache-Control: no-store` on auth HTTP. Rotate previous-hash 60s grace.
- Draft PR #2 kept. Did not merge. Did not start P1.3.

## 2026-08-30 — P1.2 customer OIDC + opaque sessions

- Branch `feat/p1.2-oidc-sessions` from `origin/main` `f1a0771`. Did not merge. Did not touch `0003` or the P1.1 kernel.
- A: `0004_team_oidc_sessions.sql` + TeamSql Neon one-connection transactions.
- B: env OIDC loader (WeakMap secrets), PKCE S256, AES-GCM seal, outbound SSRF gate, local JWKS, ID token verify.
- C: hashed pending, tenant-bound opaque sessions, `__Host-` cookie, login/callback/logout/session routes. No JIT.
- D: P1.2 gates + adversarial tests (claims ignored, slug bind, replay, CSRF logout, no createRemoteJWKSet, 0003 untouched) and docs (ADR-034, threat model, HANDOFF/BACKLOG).
- Next: P1.3 only if asked. Draft PR, do not merge.

## 2026-08-30 — P1.1 merged to main

- Squash-merged PR #1 at HEAD `ed7f913` → `main` `fa21439` (`feat(p1): add tenant isolation kernel`).
- Pre-merge check: PR head still `ed7f913`; CI run 23 belonged to that SHA.
- CI on `main` run 24 green: 418 tests / 414 pass / 4 skip / 0 fail; typecheck, lint, audit:deps, build.
- Not started: P1.2.

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
