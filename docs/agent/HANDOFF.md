# ClaimForge handoff

1. **Repo:** `ThienPhuc-2005/ClaimForge`. `main` is P1.2 squash **`6de17a4`** (PR #2). P1.3 work is on `feat/p1.3-rbac-http` (draft, not merged).
2. **Milestone:** v0.9 Core Hardening (P0 done) · P1.0–P1.2 **merged**. P1.3 RBAC HTTP **implemented, draft PR, not merged**.
3. **Done:** P0.1–P0.8. P1.0 ADRs + `docs/P1_TEAM_ISOLATION.md`. P1.1 kernel. P1.2 OIDC + opaque sessions + operator CLI. P1.3: live `team_member.role` RBAC; viewer read-only; `accepted-risk` lead+; admin+ member HTTP; last-owner protection; JWT/`ctx.role` ignored. P1.3-R1 extra HTTP cases (no Bearer, session omits role, analyst/lead cannot escalate). ADR-036.
4. **Not done:** P1.4 audit, P1.5 collab HTTP, P1.6 Team UI, encrypted capture share. Draft P1.3 PR — do not merge from this implementing session.
5. **Tests:** see `TEST_STATUS.md`. Skip count still 4 (sandbox docs / og skill) on GitHub checkout.
6. **Invariants:** `VITE_AUTH_ENABLED=false`; Team must not use `authMiddleware`/`requireUserId`; no raw HAR/JWT/cookie persist; bootstrap is operator-only CLI; OIDC fail-closed without env; session hash-only and tenant-bound; RBAC is the live member row; CI is not merge-enforced until a ruleset exists.
7. **Next step:** P1.4 only if asked. Do not merge P1.3. Do not start P1.4/P1.5/P1.6 in this epic.
8. **CI (main, P1.2 squash):** wait for Actions on `6de17a4`.
