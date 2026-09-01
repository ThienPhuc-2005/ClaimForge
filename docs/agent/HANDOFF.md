# ClaimForge handoff

Read this file first. Then `docs/P1_TEAM_ISOLATION.md` and `docs/agent/DECISIONS.md`. Do not invent a parallel product.

## Cold start (new chat — read this box first)

This is **not** a new App Builder scaffold. The product is **ClaimForge** at `ThienPhuc-2005/ClaimForge`. The sandbox `/workspace` is **not** the repo (it only has the App Builder shell). Clone GitHub; work on the stacked branch below.

**STOP — do not re-implement P1.4, P1.5, or P1.6.** They are already stacked as **draft** PRs. CI is green. The last user pick (2026-09-01) was **keep drafts / do not merge**.

| | SHA | PR | CI |
|---|---|---|---|
| `main` (P1.3 + docs) | `944f81b` | — | [run 35](https://github.com/ThienPhuc-2005/ClaimForge/actions/runs/33456608096) |
| P1.4 audit | `83059bb` | draft [#4](https://github.com/ThienPhuc-2005/ClaimForge/pull/4) | [run 36](https://github.com/ThienPhuc-2005/ClaimForge/actions/runs/33464637787) |
| P1.5 collab HTTP | `9e3c4ee` | draft [#5](https://github.com/ThienPhuc-2005/ClaimForge/pull/5) | [run 37](https://github.com/ThienPhuc-2005/ClaimForge/actions/runs/33466195709) |
| P1.6 More → Team | **branch `feat/p1.6-team-ui`** (product `914eb27`) | draft [#6](https://github.com/ThienPhuc-2005/ClaimForge/pull/6) | [run 39](https://github.com/ThienPhuc-2005/ClaimForge/actions/runs/33470971472); later docs commit is handoff only |

Merging **PR #6** lands P1.4 + P1.5 + P1.6 together. **Do not merge** unless the user picks merge. `main` HANDOFF at `944f81b` is **stale** (it still says “P1.4 not started”). This file on `feat/p1.6-team-ui` is the live handoff.

If the user says **tiếp** after a picker: that means continue the **in-progress slice**, not start encrypted capture share. Capture share is **not P1** (needs a new threat model). After P1.6 the default is merge-or-wait.

## Snapshot (2026-09-01, post-P1.6, drafts held)

1. **Repo:** `ThienPhuc-2005/ClaimForge`. Working tree on this branch is clean except an untracked `node_modules` symlink in some sandboxes — never commit it.
2. **Milestone:** v0.9 Core Hardening. **P0 + P1.0–P1.3 merged** to `main`. **P1.4–P1.6 implemented, unmerged, CI green.**
3. **Done on main:** P0.1–P0.8. P1.1 isolation kernel. P1.2 OIDC + opaque sessions + operator CLI. P1.3 live `team_member.role` RBAC + session-bound `/api/team/members`. ADR-036. A3 lab 36/36 (sandbox-only, not in git).
4. **Unmerged stack (this branch):** P1.4 append-only audit (`0005`, ADR-037). P1.5 session-bound collab HTTP (ADR-038). P1.6 More → Team inspect view (ADR-039). Tests on this branch: **509 / 505 pass / 4 skip / 0 fail** (GitHub checkout).
5. **P1.6 product:** Solo stays the default desk. Team is **More → Team**, not a primary tab. Slug sign-in (`GET /api/team/oidc/login?slug=`). No tenant list. Session JSON `{userKey, tenantId}` — **no role**; live role comes from the members list. Push policy/review/ReportDTO; kernel still projects loot/replay. Pull applies policy + review, does not restore captures. Loot/replay copy in the tab is local (ADR-027). Callback opens `/?team=1`. Client is `src/lib/team/client.ts` (same-origin cookie, never sends `tenant_id`).
6. **Not done:** encrypted capture share, tenant listing, IdP logout, OIDC discovery, JIT, Postgres RLS claim, HMAC-IP.
7. **Invariants (do not break):**
   - `VITE_AUTH_ENABLED=false`. Team must not import `authMiddleware` / `requireUserId` / `@/lib/auth/server`.
   - No raw HAR / JWT compact / cookie / credentials persist. Collab is policy + review + Team ReportDTO projection (`loot.value` and `replays.raw`/`curl` = `[redacted]`).
   - First tenant/owner = operator CLI only (`npm run team:bootstrap`). No public bootstrap. No JIT.
   - Session cookie `__Host-claimforge-team.session`: opaque, DB stores SHA-256 only, tenant-bound, CASCADE on member delete. `GET /api/team/session` = `{userKey, tenantId}` — **no role**.
   - RBAC authority is the **live** `team_member.role` re-SELECT (`requireActiveMember`). JWT `role` / minted `ctx.role` are not authority.
   - Same-tenant denial = 403 `forbidden`. Missing / cross-tenant = 404 `not found`.
   - `owner` cannot be assigned after bootstrap. Last owner cannot be removed or demoted.
   - Audit actor is the live member, not a client id. No IP / `sha256(ip)` / UA columns. No capture/JWKS in `detail_json`.
   - CI green is **evidence**, not a merge gate (ADR-029). `main` has no branch protection.
8. **Process the user expects:**
   - Implement on `feat/p1.N-…`. Open a **draft** PR. **Do not merge** from the implementing session unless the user says merge.
   - After a slice: typecheck, lint, `npm test`, audit, build. Push. Wait for Actions. Update the PR body with the CI run link.
   - Talk to the user in **Vietnamese**, product terms (no ports/paths/`localhost`/tool names unless they ask).
   - **Every time you finish a slice, end with a short numbered command picker** (what it does + whether it increases bug-finding). Wait for them to pick. Do not auto-start the next epic.
9. **Next step:** only what the user picks. Default is keep-drafts or merge P1.4→P1.6. Do not start capture-share unless they name it.

## Key paths

| Area | Path |
|------|------|
| Architecture | `docs/P1_TEAM_ISOLATION.md` |
| ADRs | `docs/agent/DECISIONS.md` (017–039) |
| Kernel | `src/lib/team/repo.ts`, `context.ts`, `rbac.ts` |
| Audit | `src/lib/team/audit.ts`, `audit-http.ts`, `migrations/0005_team_audit.sql` |
| Collab HTTP | `src/lib/team/collab-http.ts`, `src/routes/api/team/collab.ts`, `src/routes/api/team/workspaces.ts` |
| Team UI | `src/components/team-view.tsx`, `src/lib/team/client.ts`, `src/lib/team/ui.ts` |
| Sessions / OIDC | `src/lib/team/session.ts`, `oidc-*.ts`, `cookie.ts` |
| Members HTTP | `src/lib/team/rbac-http.ts`, `src/routes/api/team/members.ts` |
| Gates | `src/lib/team/p1-gates.ts`, `p1-6-*.test.ts`, `p1-5-*.test.ts`, `p1-4-*.test.ts`, `p1-3-*.test.ts`, `p1-2-*.test.ts`, `p1-isolation.test.ts` |
| Schema | `migrations/0003_team_isolation.sql`, `0004_team_oidc_sessions.sql`, `0005_team_audit.sql` |
| Operator | `scripts/team-bootstrap.mjs`, `docs/operator/BOOTSTRAP.md` |

## Command picker (paste at end of every turn)

| # | Lệnh | Làm gì | Tăng tìm lỗi? |
|---|---|---|---|
| **1** | **Giữ PR nháp** | Không merge; CI là evidence | Có — CI trên nhánh |
| **2** | **Merge P1.4 → P1.6** | Đưa audit + collab HTTP + UI vào `main` | Có — CI trên `main` |
| **3** | **Giữ `main`** | Không code thêm | Không |
