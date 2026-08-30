# ClaimForge handoff

1. **Repo:** `ThienPhuc-2005/ClaimForge` · verified `main` snapshot **`f1ed912`** (CI run 20). Implementation of P1 lives on **`feat/p1-isolation-kernel`**, not `main`.
2. **Milestone:** v0.9 Core Hardening (P0 done) · P1 Team isolation.
3. **This docs commit:** P1.0 architecture only. Do not treat this file as recording its own SHA.
4. **Done:** P0.1–P0.8. P1.0 ADRs + `docs/P1_TEAM_ISOLATION.md`.
5. **Not done:** P1.1 kernel (next commit on this branch). P1.2 OIDC/sessions, P1.3 RBAC HTTP, UI, capture upload.
6. **Tests:** unchanged by this docs commit. Last green on `main`: CI run 20 — 387 tests, 383 pass, 4 skip, 0 fail.
7. **Invariants already decided:** `VITE_AUTH_ENABLED=false`; Team must not use `authMiddleware`/`requireUserId`; no raw HAR/JWT/cookie persist; bootstrap is operator-only; CI is not merge-enforced until a ruleset exists.
8. **Next step:** P1.1 isolation kernel on this branch. Do not start P1.2 unless asked.
9. **CI (main):** https://github.com/ThienPhuc-2005/ClaimForge/actions/runs/33292274694
