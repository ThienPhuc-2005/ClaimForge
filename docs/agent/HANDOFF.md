# ClaimForge handoff

1. **Repo:** `ThienPhuc-2005/ClaimForge` · branch `main` · **HEAD pending push (remainder commit on `main`)**.
2. **Milestone:** v0.9 Core Hardening · **item:** remainder P0 + CI gates (done).
3. **Session goal (done):** Policy regex errors, role-hierarchy scoring, JWKS allowlist boundary, paginated PDF, CI (build + audit + all first-party tests). No Team backend.
4. **Done:** P0.1–P0.8 including remainder: regex validation UI, role-hierarchy scoring, JWKS closed allowlist in every mode, paginated PDF, CI required gates.
5. **Not done:** P1 Team/OIDC. DNS rebinding still in-browser limited. PDF layout polish is P3.
6. **Tests:** `npm test` **387 pass / 0 fail**; `npm run typecheck`; `npm run lint`; `npm run audit:deps` (0 high); `npm run build`.
7. **Browser:** Load lab → More → Policy: invalid `(unclosed` shows regex error and does not Apply. Hierarchy `admin: user, viewer` changelog: mass-assign observation/high → confirmed/high. JWKS allowlist field present. Export PDF no console errors. Dev smoke desktop+mobile clean.
8. **Working tree:** clean vs `origin/main` after this push except untracked `attachments/` (spec dump, not part of the app).
9. **Next step only:** P1 Team backend **only if asked**. Remainder + CI are green.
10. **CI:** https://github.com/ThienPhuc-2005/ClaimForge/actions
