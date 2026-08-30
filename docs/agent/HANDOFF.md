# ClaimForge handoff

1. **Repo:** `ThienPhuc-2005/ClaimForge` · branch `main` · verified base `6c3ba6f`.
2. **Milestone:** v0.9 Core Hardening · **item:** P0.1 policy editor remainder (this session).
3. **Session goal:** Analyst policy editor + re-run changelog. No Team backend. No app rewrite.
4. **Done:**
   - More → Policy editor (patterns, ownership fields, statuses, iss/aud, logout, roles).
   - Apply bumps version, re-runs analyze, diffs findings by fingerprint.
   - Policy drives public/shared classification and extra ownership keys.
5. **Not done:** Role hierarchy scoring, Team OIDC, PDF layout, JWKS DNS pin.
6. **Tests:** `npm run test:claimforge` 151 pass; typecheck; lint. Browser: invoices-as-public demotes lab BOLA.
7. **Risks:** Invalid regex is skipped silently. Role hierarchy is data-only.
8. **Working tree:** dirty until this session's commit.
9. **Next step only:** P0 is green including the editor. Do **not** start Team unless explicitly asked.
10. **Next-session prompt:** Continue from repo. Read `docs/agent/HANDOFF.md`. Only start P1 Team if the user asks.
