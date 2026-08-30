# ClaimForge handoff

1. **Repo:** `ThienPhuc-2005/ClaimForge` · branch `main` · verified base `d459054`.
2. **Milestone:** v0.9 Core Hardening · **item:** P0.8 Adversarial gate completeness (this session).
3. **Session goal:** Each P0.1–P0.7 bug has a fail-then-pass test. No Team backend. No app rewrite.
4. **Done:**
   - `p0-gates.ts` catalog (before/after + evidence test).
   - `p0-adversarial-gate.test.ts` fills gaps: path-as-owner, wordlist formulas, JWT canary, JWKS omit+audit, CORS *+credentials.
5. **Not done:** Policy editor UI, Team OIDC, PDF layout, JWKS DNS pin.
6. **Tests:** `npm run test:claimforge` 143 pass; typecheck; lint. See `TEST_STATUS.md`.
7. **Risks:** Catalog completeness is file-existence + unique ids, not a mutation of production analyzers. Reverting a P0 fix should fail the named evidence test.
8. **Working tree:** dirty until this session's commit.
9. **Next step only:** P0 slices are green. Do **not** start Team unless explicitly asked. Optional remainder: policy editor UI (P0.1 gap).
10. **Next-session prompt:** Continue from repo. Read `docs/agent/HANDOFF.md`. P0 is green as slices. Only start P1 Team if the user asks. Otherwise stop or do the policy editor UI gap only.
