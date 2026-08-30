# ClaimForge handoff

1. **Repo:** `ThienPhuc-2005/ClaimForge` · branch `main` · verified base `0484b53`.
2. **Milestone:** v0.9 Core Hardening · **item:** P0.5 Forge revision machine (this session).
3. **Session goal:** Unsigned draft / Signed output / Stale output; void signed compact JWT when header, payload, alg, HMAC, PEM, JWKS, kid, iss, or aud changes; block copy of stale signed token.
4. **Done:**
   - `forge-revision.ts` state machine.
   - Forge UI badges + signed copy disabled when stale.
   - Tests in `p0-forge-revision.test.ts` for every listed field.
5. **Not done:** P0.6 JWKS network/SSRF, policy editor UI, Team/OIDC.
6. **Tests:** `npm run test:claimforge` 117 pass; typecheck; lint.
7. **Risks:** Unsigned draft remains copyable while signed is stale (intentional). JWKS fetch still user-initiated without SSRF hardening (P0.6).
8. **Working tree:** dirty until push.
9. **Next step only:** P0.6 JWKS network security — HTTPS-only (localhost HTTP exception), confirm dialog, timeout/size/content-type, no secrets in logs. No Team backend.
10. **Next-session prompt:** Continue from repo. Read `docs/agent/HANDOFF.md`. Only implement P0.6 JWKS network guards + tests. Update handoff before exit.
