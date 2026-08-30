# ClaimForge handoff

1. **Repo:** `ThienPhuc-2005/ClaimForge` · `main`. P1.1 squash is **`fa21439`**. This file is a follow-up record; do not treat it as recording its own SHA.
2. **Milestone:** v0.9 Core Hardening (P0 done) · P1.0 architecture + P1.1 isolation kernel **merged**.
3. **Done:** P0.1–P0.8. P1.0 ADRs + `docs/P1_TEAM_ISOLATION.md`. P1.1 kernel (PR #1 squash): frozen WeakMap `TenantContext` minted only after bootstrap INSERT or membership SELECT; `requireActiveMember` (snapshot + live `team_member` SELECT) is SQL authority, never `ctx.tenantId`; Team ReportDTO projection (`loot.value` and `replays.raw`/`curl` always `[redacted]`) then canary scan; composite FK; atomic collab UPSERT; adversarial tests. No HTTP, no UI, no OIDC.
4. **Not done:** P1.2 customer OIDC + opaque sessions, P1.3 RBAC HTTP, P1.4 audit, P1.5 collab HTTP, P1.6 Team UI, encrypted capture share.
5. **Tests:** see `TEST_STATUS.md`. Skip count still 4 (sandbox docs / og skill) on GitHub checkout.
6. **Invariants:** `VITE_AUTH_ENABLED=false`; Team must not use `authMiddleware`/`requireUserId`; no raw HAR/JWT/cookie persist; bootstrap is operator-only; CI is not merge-enforced until a ruleset exists.
7. **Next step:** P1.2 only if asked. Do not start it in the merge session.
8. **CI (main, P1.1 squash):** https://github.com/ThienPhuc-2005/ClaimForge/actions/runs/33304174040
