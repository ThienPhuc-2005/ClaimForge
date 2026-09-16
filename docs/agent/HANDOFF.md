# ClaimForge handoff

Read this file first. Then `docs/P1_TEAM_ISOLATION.md` and `docs/agent/DECISIONS.md`. Do not invent a parallel product.

## Cold start (new chat — read this box first)

This is **not** a new App Builder scaffold. The product is **ClaimForge** at `ThienPhuc-2005/ClaimForge`. The sandbox `/workspace` is **not** the repo (it only has the App Builder shell). Clone GitHub; checkout **`main`**.

**STOP — do not re-implement P1.4–P1.7.** They are **merged**. Encrypted capture share is **not P1** (needs a new threat model) — do not start it unless the user names it.

| | SHA | PR | CI |
|---|---|---|---|
| `main` product (P1.7 squash) | `9cbd88d` | merged [#7](https://github.com/ThienPhuc-2005/ClaimForge/pull/7) | [run 33509604074](https://github.com/ThienPhuc-2005/ClaimForge/actions/runs/33509604074) success |
| Prior `main` (P1.4–P1.6 + A-lab docs) | `24af162` | merged [#6](https://github.com/ThienPhuc-2005/ClaimForge/pull/6) | [run 41](https://github.com/ThienPhuc-2005/ClaimForge/actions/runs/33500312474) success |

User pick **2 = ghi A-lab lên main** (2026-09-01). Reconfirmed A-lab Chromium+Postgres **31/31** (sandbox-only). Do not start capture-share unless they name it. This file on `main` is the live handoff.

**P2 in progress on branch `claude/optimistic-bell-v95isp` (NOT merged, 2026-09-16).** User asked to "make the app stronger / làm hết". Added, within the existing no-network threat model: **BFLA**, **CSRF**, **refresh-token reuse** detections; **OpenAPI/Swagger coverage** (JSON-only offline surface diff); **scale** (24MB / 4000-per-actor) with visible truncation. Held **C = active verification / encrypted capture share** for explicit consent (changes app nature; needs a new threat model). ADR-041/042/043. `ENGINE_VERSION 0.9.0-p2.0`, `RULE_VERSION bola-trust-2`. Ran an attack→verify adversarial-review workflow and fixed the real FPs/FNs with regression tests before commit. See the 2026-09-16 SESSION_LOG entry. Not merged; no PR unless the user asks.

If the user says **tiếp** after a picker: that means continue the **in-progress slice**, not start encrypted capture share. There is **no in-progress slice**. Default is keep-`main`. Do not auto-start the next epic.

## Snapshot (2026-09-01, after A-lab reconfirm)

1. **Repo:** `ThienPhuc-2005/ClaimForge`. Working tree on `main` is clean except an untracked lab script in some sandboxes — never commit it.
2. **Milestone:** v0.9 Core Hardening. **P0 + P1.0–P1.7 merged** to `main`.
3. **Done on main:** P0.1–P0.8. P1.1 isolation kernel. P1.2 OIDC + opaque sessions + operator CLI. P1.3 live `team_member.role` RBAC. P1.4 append-only audit (ADR-037). P1.5 session-bound collab HTTP (ADR-038). P1.6 More → Team (ADR-039). P1.7 Postgres RLS fail-closed GUC (ADR-040, `0006`). Tests: **512**. GitHub checkout skips sandbox-doc tests (4). CI Postgres service runs the RLS test.
4. **P1.6 product:** Solo stays the default desk. Team is **More → Team**, not a primary tab. Slug sign-in. No tenant list. Session JSON `{userKey, tenantId}` — **no role**; live role comes from the members list. Push policy/review/ReportDTO; kernel still projects loot/replay. Pull applies policy + review, does not restore captures. Loot/replay copy in the tab is local (ADR-027). Callback opens `/?team=1`.
5. **P1.7 product:** FORCE RLS on member/workspace/collab/audit. Missing `claimforge.tenant_id` hides rows. Kernel SET LOCAL from the WeakMap snapshot. Lookup tables (tenant/pending/session) are not RLS'd. PGLite does not enforce RLS. A stolen app role that knows a tenant UUID can still SET the GUC.
6. **Not done:** encrypted capture share, tenant listing, IdP logout, OIDC discovery, JIT, HMAC-IP. P1.4–P1.7 A-lab Chromium+Postgres **31/31** reconfirmed (sandbox-only; Firefox skipped; includes FORCE RLS).
7. **Invariants (do not break):**
   - `VITE_AUTH_ENABLED=false`. Team must not import `authMiddleware` / `requireUserId` / `@/lib/auth/server`.
   - No raw HAR / JWT compact / cookie / credentials persist. Collab is policy + review + Team ReportDTO projection (`loot.value` and `replays.raw`/`curl` = `[redacted]`).
   - First tenant/owner = operator CLI only (`npm run team:bootstrap`). No public bootstrap. No JIT.
   - Session cookie `__Host-claimforge-team.session`: opaque, DB stores SHA-256 only, tenant-bound, CASCADE on member delete. `GET /api/team/session` = `{userKey, tenantId}` — **no role**.
   - RBAC authority is the **live** `team_member.role` re-SELECT (`requireActiveMember`). JWT `role` / minted `ctx.role` are not authority.
   - Same-tenant denial = 403 `forbidden`. Missing / cross-tenant = 404 `not found`.
   - `owner` cannot be assigned after bootstrap. Last owner cannot be removed or demoted.
   - Audit actor is the live member, not a client id. No IP / `sha256(ip)` / UA columns. No capture/JWKS in `detail_json`.
   - RLS GUC is set from the verified snapshot, never from caller `tenant_id`.
   - CI green is **evidence**, not a merge gate (ADR-029). `main` has no branch protection.
8. **Process the user expects:**
   - Implement on `feat/p1.N-…`. Open a **draft** PR. **Do not merge** from the implementing session unless the user says merge.
   - After a slice: typecheck, lint, `npm test`, audit, build. Push. Wait for Actions. Update the PR body with the CI run link.
   - Talk to the user in **Vietnamese**, product terms (no ports/paths/`localhost`/tool names unless they ask).
   - **Every time you finish a slice, end with a short numbered command picker** (what it does + whether it increases bug-finding). Wait for them to pick. Do not auto-start the next epic.
   - Propose a default pick; do not force them to invent the next epic.
9. **Next step:** default is keep-`main`. Clone GitHub, checkout `main`, read this file. Do not scaffold. Do not re-implement P1.4–P1.7. Do not start capture-share unless they name it.

## Key paths

| Area | Path |
|------|------|
| Architecture | `docs/P1_TEAM_ISOLATION.md` |
| ADRs | `docs/agent/DECISIONS.md` (017–040) |
| Kernel | `src/lib/team/repo.ts`, `context.ts`, `rbac.ts` |
| Audit | `src/lib/team/audit.ts`, `audit-http.ts`, `migrations/0005_team_audit.sql` |
| Collab HTTP | `src/lib/team/collab-http.ts`, `src/routes/api/team/collab.ts`, `src/routes/api/team/workspaces.ts` |
| Team UI | `src/components/team-view.tsx`, `src/lib/team/client.ts`, `src/lib/team/ui.ts` |
| Sessions / OIDC | `src/lib/team/session.ts`, `oidc-*.ts`, `cookie.ts` |
| Members HTTP | `src/lib/team/rbac-http.ts`, `src/routes/api/team/members.ts` |
| RLS | `migrations/0006_team_rls.sql`, `src/lib/team/p1-7-rls.test.ts` |
| Gates | `src/lib/team/p1-gates.ts`, `p1-7-*.test.ts`, `p1-6-*.test.ts`, `p1-5-*.test.ts`, `p1-4-*.test.ts`, `p1-3-*.test.ts`, `p1-2-*.test.ts`, `p1-isolation.test.ts` |
| Schema | `migrations/0003_team_isolation.sql`, `0004_team_oidc_sessions.sql`, `0005_team_audit.sql`, `0006_team_rls.sql` |
| Operator | `scripts/team-bootstrap.mjs`, `docs/operator/BOOTSTRAP.md` |

## Command picker (paste at end of every turn)

| # | Lệnh | Làm gì | Tăng tìm lỗi? |
|---|---|---|---|
| **1** | **Xem lại / gộp P2** | Review nhánh `claude/optimistic-bell-v95isp`, mở PR hoặc gộp khi bạn duyệt | Không (đã có) |
| **2** | **Lab A cho P2** | Trình duyệt + Postgres trên BFLA / CSRF / refresh / spec coverage | Có |
| **3** | **Làm C — xác minh chủ động** | Mở threat model mới cho việc gửi gói tin thật (cần bạn nêu tên rõ) | Có, nhưng đổi bản chất app |
| **4** | **Giữ `main`** | Không code thêm | Không |
