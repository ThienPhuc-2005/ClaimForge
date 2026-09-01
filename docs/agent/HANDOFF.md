# ClaimForge handoff

Read this file first. Then `docs/P1_TEAM_ISOLATION.md` and `docs/agent/DECISIONS.md`. Do not invent a parallel product.

## Snapshot (2026-09-01)

1. **Repo:** `ThienPhuc-2005/ClaimForge`. `main` = **`944f81b`** (handoff after P1.3 squash `4cefe02`, [PR #3](https://github.com/ThienPhuc-2005/ClaimForge/pull/3)). Implementing P1.4 on **`feat/p1.4-audit`** — draft PR, **do not merge** unless the user says merge.
2. **Milestone:** v0.9 Core Hardening. **P0 + P1.0–P1.3 merged.** This slice is **P1.4 audit**.
3. **Done on main:** P0.1–P0.8. P1.1 isolation kernel. P1.2 OIDC + opaque sessions + operator CLI. P1.3 live `team_member.role` RBAC + session-bound `/api/team/members`. ADR-036.
4. **This branch:** append-only `team_audit` (0005), kernel logs member/workspace/collab changes, `GET /api/team/audit`, ADR-037. IP/UA omitted. Actor is the live member row. Member delete does not erase rows.
5. **Not done:** P1.5 collab HTTP, P1.6 Team UI, encrypted capture share, tenant listing, IdP logout, OIDC discovery, JIT, Postgres RLS claim, HMAC-IP.
6. **Invariants (do not break):**
   - `VITE_AUTH_ENABLED=false`. Team must not import `authMiddleware` / `requireUserId` / `@/lib/auth/server`.
   - No raw HAR / JWT compact / cookie / credentials persist. Collab is policy + review + Team ReportDTO projection (`loot.value` and `replays.raw`/`curl` = `[redacted]`).
   - First tenant/owner = operator CLI only (`npm run team:bootstrap`). No public bootstrap. No JIT.
   - Session cookie `__Host-claimforge-team.session`: opaque, DB stores SHA-256 only, tenant-bound, CASCADE on member delete. `GET /api/team/session` = `{userKey, tenantId}` — **no role**.
   - RBAC authority is the **live** `team_member.role` re-SELECT (`requireActiveMember`). JWT `role` / minted `ctx.role` are not authority.
   - Same-tenant denial = 403 `forbidden`. Missing / cross-tenant = 404 `not found`.
   - `owner` cannot be assigned after bootstrap. Last owner cannot be removed or demoted.
   - Audit actor is the live member, not a client id. No IP / `sha256(ip)` / UA columns. No capture/JWKS in `detail_json`.
   - CI green is **evidence**, not a merge gate (ADR-029). `main` has no branch protection.
7. **Process the user expects:**
   - Implement on `feat/p1.N-…`. Open a **draft** PR. **Do not merge** from the implementing session unless the user says merge.
   - After a slice: typecheck, lint, `npm test`, audit, build. Push. Wait for Actions.
   - Talk to the user in **Vietnamese**, product terms (no ports/paths/`localhost`/tool names unless they ask).
   - **Every time you finish a slice, end with a short numbered command picker** (what it does + whether it increases bug-finding). Wait for them to pick. Do not auto-start the next epic.
8. **Next step:** only what the user picks. Default product order after this draft is merge-or-wait, then P1.5 → P1.6.

## Key paths

| Area | Path |
|------|------|
| Architecture | `docs/P1_TEAM_ISOLATION.md` |
| ADRs | `docs/agent/DECISIONS.md` (017–037) |
| Kernel | `src/lib/team/repo.ts`, `context.ts`, `rbac.ts` |
| Audit | `src/lib/team/audit.ts`, `audit-http.ts`, `migrations/0005_team_audit.sql` |
| Sessions / OIDC | `src/lib/team/session.ts`, `oidc-*.ts`, `cookie.ts` |
| Members HTTP | `src/lib/team/rbac-http.ts`, `src/routes/api/team/members.ts` |
| Gates | `src/lib/team/p1-gates.ts`, `p1-4-*.test.ts`, `p1-3-*.test.ts`, `p1-2-*.test.ts`, `p1-isolation.test.ts` |
| Schema | `migrations/0003_team_isolation.sql`, `0004_team_oidc_sessions.sql`, `0005_team_audit.sql` |
| Operator | `scripts/team-bootstrap.mjs`, `docs/operator/BOOTSTRAP.md` |

## P1.5 if asked (spec, not built)

Collab HTTP for policy/review/ReportDTO over the session. Persist allowlist is already a kernel invariant. Tenant-scoped. Draft PR; do not merge unless asked.

## Command picker (paste at end of every turn)

| # | Lệnh | Làm gì | Tăng tìm lỗi? |
|---|---|---|---|
| **1** | **Mở PR nháp P1.4** | Đưa audit lên review, chưa merge | Có — CI trên nhánh |
| **2** | **P1.5 collab HTTP** | API lưu policy/review theo session | Có — bắt IDOR giữa tenant |
| **3** | **Giữ nhánh / `main`** | Không code thêm | Không |
