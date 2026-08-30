# ClaimForge handoff

1. **Repo:** `ThienPhuc-2005/ClaimForge` · branch `main` · **repair `e16575e71f0adbf00efc5b6404594d5b3b10decd`**. This handoff snapshot is the tip of `main` once committed.
2. **Milestone:** v0.9 Core Hardening · **item:** remainder P0 + CI gates (done).
3. **Session goal (done):** Record true HEAD vs `8740c6f`, finish remainder P0, raise CI (build + audit + all first-party tests). No Team backend.
4. **Done:** P0.1–P0.8 including remainder: regex Apply block (`policyApplyDecision`), role-hierarchy scoring (Confirmed ROLE_ESCALATION, not Critical; empty tree never escalates), JWKS closed allowlist in every mode, paginated PDF with How + page numbers. CI: typecheck, lint, `npm test`, `audit:deps`, production build.
5. **Not done:** P1 Team/OIDC. DNS rebinding still in-browser limited. PDF layout polish is P3.
6. **Tests:** `npm test` **387 pass / 0 fail** locally; GitHub-checkout sim **383 pass / 4 skip** (sandbox-doc tripwires). `npm run typecheck`; `npm run lint`; `npm run audit:deps` (0 high); `npm run build`.
7. **Browser:** Load lab → More → Policy: invalid `(unclosed` shows regex error and does not Apply. Hierarchy `admin: user, viewer` changelog: mass-assign observation/high → confirmed/high. JWKS allowlist field present. Export PDF no console errors.
8. **Working tree:** clean vs this snapshot except untracked `attachments/` (spec dump, not part of the app).
9. **Next step only:** P1 Team backend **only if asked**. Remainder + CI repair are green locally; confirm GitHub Actions on this push.
10. **CI:** https://github.com/ThienPhuc-2005/ClaimForge/actions
    Last red on previous HEAD: https://github.com/ThienPhuc-2005/ClaimForge/actions/runs/33291720368
