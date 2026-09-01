# ClaimForge handoff

Read this file first. Then `docs/P1_TEAM_ISOLATION.md` and `docs/agent/DECISIONS.md`. Do not invent a parallel product.

## Snapshot (2026-09-01)

1. **Repo:** `ThienPhuc-2005/ClaimForge`. `main` = **`4cefe02`** (P1.3 squash, [PR #3](https://github.com/ThienPhuc-2005/ClaimForge/pull/3)). Working tree clean except untracked `node_modules` symlink in some sandboxes.
2. **Milestone:** v0.9 Core Hardening. **P0 + P1.0–P1.3 merged.** Next product epic is **P1.4 audit** (not started).
3. **Done:** P0.1–P0.8. P1.1 isolation kernel. P1.2 OIDC + opaque sessions + operator CLI. P1.3 live `team_member.role` RBAC + session-bound `/api/team/members`. ADR-036.
4. **Not done:** P1.4 append-only audit, P1.5 collab HTTP, P1.6 Team UI, encrypted capture share, tenant listing, IdP logout, OIDC discovery, JIT, Postgres RLS claim.
5. **Tests on `4cefe02`:** `npm test` **482 / 478 pass / 4 skip / 0 fail** (GitHub checkout). typecheck, lint, audit:deps 0 high, build pass. CI [run 34 success](https://github.com/ThienPhuc-2005/ClaimForge/actions/runs/33454015932). P1.3-A3 browser lab **36/36 PASS** (Chromium + Firefox + PostgreSQL 16.6, real `__Host-` cookies). Lab is sandbox-only; not in git.
6. **Invariants (do not break):**
   - `VITE_AUTH_ENABLED=false`. Team must not import `authMiddleware` / `requireUserId` / `@/lib/auth/server`.
   - No raw HAR / JWT compact / cookie / credentials persist. Collab is policy + review + Team ReportDTO projection (`loot.value` and `replays.raw`/`curl` = `[redacted]`).
   - First tenant/owner = operator CLI only (`npm run team:bootstrap`). No public bootstrap. No JIT.
   - Session cookie `__Host-claimforge-team.session`: opaque, DB stores SHA-256 only, tenant-bound, CASCADE on member delete. `GET /api/team/session` = `{userKey, tenantId}` — **no role**.
   - RBAC authority is the **live** `team_member.role` re-SELECT (`requireActiveMember`). JWT `role` / minted `ctx.role` are not authority.
   - Same-tenant denial = 403 `forbidden`. Missing / cross-tenant = 404 `not found`.
   - `owner` cannot be assigned after bootstrap. Last owner cannot be removed or demoted.
   - CI green is **evidence**, not a merge gate (ADR-029). `main` has no branch protection.
7. **Process the user expects:**
   - Implement on `feat/p1.N-…`. Open a **draft** PR. **Do not merge** from the implementing session unless the user says merge.
   - After a slice: typecheck, lint, `npm test`, audit, build. Push. Wait for Actions.
   - Talk to the user in **Vietnamese**, product terms (no ports/paths/`localhost`/tool names unless they ask).
   - **Every time you finish a slice, end with a short numbered command picker** (what it does + whether it increases bug-finding). Wait for them to pick. Do not auto-start the next epic.
8. **Next step:** only what the user picks. Default product order is P1.4 → P1.5 → P1.6. Do not start P1.4 until they say so.

## Key paths

| Area | Path |
|------|------|
| Architecture | `docs/P1_TEAM_ISOLATION.md` |
| ADRs | `docs/agent/DECISIONS.md` (017–036) |
| Kernel | `src/lib/team/repo.ts`, `context.ts`, `rbac.ts` |
| Sessions / OIDC | `src/lib/team/session.ts`, `oidc-*.ts`, `cookie.ts` |
| Members HTTP | `src/lib/team/rbac-http.ts`, `src/routes/api/team/members.ts` |
| Gates | `src/lib/team/p1-gates.ts`, `p1-3-*.test.ts`, `p1-2-*.test.ts`, `p1-isolation.test.ts` |
| Schema | `migrations/0003_team_isolation.sql`, `0004_team_oidc_sessions.sql` |
| Operator | `scripts/team-bootstrap.mjs`, `docs/operator/BOOTSTRAP.md` |

## P1.4 if asked (spec, not built)

Append-only audit of who changed whose collab/membership. No capture bodies, no JWKS material. **Never** store raw IP or `sha256(ip)` — omit IP or `HMAC(ip, rotating_server_key)` with rotation and no raw IP beside it (ADR-023). User-agent: omit or HMAC. Additive migration `0005_…`. Tenant-scoped reads. Actor is the live session member, not a client-supplied id. Draft PR; do not merge unless asked.

## P1.3-A3 lab (sandbox, not in repo)

`/tmp/p13a3-lab/run-a3-lab.mjs` + leftover `/tmp/p12a2-lab`. Real Postgres 16.6 (`/tmp/pgsql`, `unshare --user --map-user=1000`). Vite HTTPS was a **local uncommitted** `vite.config.ts` patch (restored). Do not commit TLS lab wiring. IdP JWT forges `role: superadmin` — session still omits role.

## Command picker (paste at end of every turn)

| # | Lệnh | Làm gì | Tăng tìm lỗi? |
|---|---|---|---|
| **1** | **P1.4 audit** | Log ai sửa collab/member, không sửa được dòng cũ | Có — bắt xóa dấu vết, giả actor |
| **2** | **P1.5 collab HTTP** | API lưu policy/review theo session | Có — bắt IDOR giữa tenant |
| **3** | **Giữ `main`** | Không code thêm | Không |
