# ClaimForge handoff

1. **Repo:** `ThienPhuc-2005/ClaimForge`. Work for P1.2 is on `feat/p1.2-oidc-sessions` (not merged). `main` remains P1.1 squash **`fa21439`** / docs **`f1a0771`**.
2. **Milestone:** v0.9 Core Hardening (P0 done) · P1.0 architecture + P1.1 isolation kernel **merged**. P1.2 OIDC + opaque sessions **implemented, draft PR, not merged**.
3. **Done:** P0.1–P0.8. P1.0 ADRs + `docs/P1_TEAM_ISOLATION.md`. P1.1 kernel (PR #1 squash). P1.2: env IdP, Auth Code+PKCE S256, local JWKS verify, sealed pending, tenant-bound opaque sessions, `__Host-` cookie, login/callback/logout/session routes. P1.2-R1: stream-capped token POST, no default X-Forwarded-Proto, no slug oracle, exact sub, iat window, no-store, rotate grace. No JIT. No Better Auth.
4. **Not done:** P1.3 RBAC HTTP, P1.4 audit, P1.5 collab HTTP, P1.6 Team UI, encrypted capture share. Draft PR #2 — do not merge.
5. **Tests:** see `TEST_STATUS.md`. Skip count still 4 (sandbox docs / og skill) on GitHub checkout.
6. **Invariants:** `VITE_AUTH_ENABLED=false`; Team must not use `authMiddleware`/`requireUserId`; no raw HAR/JWT/cookie persist; bootstrap is operator-only; OIDC fail-closed without env; session hash-only and tenant-bound; CI is not merge-enforced until a ruleset exists.
7. **Next step:** P1.3 only if asked. Do not merge P1.2. Do not start P1.3/P1.5/P1.6 in this epic.
8. **CI (main, P1.1 squash):** https://github.com/ThienPhuc-2005/ClaimForge/actions/runs/33304174040
