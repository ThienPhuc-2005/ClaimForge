# ClaimForge handoff

1. **Repo:** `ThienPhuc-2005/ClaimForge` · `main` snapshot **`f1ed912`**. This work is on **`feat/p1-isolation-kernel`**. Do not treat this file as recording its own SHA.
2. **Milestone:** v0.9 Core Hardening (P0 done) · P1.0 architecture + P1.1 isolation kernel.
3. **Done:** P0.1–P0.8. P1.0 ADRs + `docs/P1_TEAM_ISOLATION.md`. P1.1 kernel: branded `TenantContext` only from bootstrap/resolve (no public `contextFromMember`), composite FK schema, strict ReportDTO schema + server re-redaction + UTF-8 caps, read-path sanitize, atomic collab upsert, adversarial tests. No HTTP, no UI, no OIDC.
4. **Not done:** P1.2 customer OIDC + opaque sessions, P1.3 RBAC HTTP, P1.4 audit, P1.5 collab HTTP, P1.6 Team UI, encrypted capture share.
5. **Tests:** see `TEST_STATUS.md`. Skip count still 4 (sandbox docs / og skill) on GitHub checkout.
6. **Invariants:** `VITE_AUTH_ENABLED=false`; Team must not use `authMiddleware`/`requireUserId`; no raw HAR/JWT/cookie persist; bootstrap is operator-only; CI is not merge-enforced until a ruleset exists.
7. **Next step:** wait CI on this HEAD via the existing PR. Do not start P1.2 unless asked. Do not merge to `main` unless asked.
8. **CI (main, pre-P1):** https://github.com/ThienPhuc-2005/ClaimForge/actions/runs/33292274694
