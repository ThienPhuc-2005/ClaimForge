# ClaimForge handoff

1. **Repo:** `ThienPhuc-2005/ClaimForge` · branch `main` · verified base `4e3f288`.
2. **Milestone:** v0.9 Core Hardening · **item:** P0.6 JWKS network security (this session).
3. **Session goal:** HTTPS-only JWKS (loopback HTTP exception), explicit confirm, timeout/size/content-type, redirect revalidation, no secrets in audit. No Team backend.
4. **Done:**
   - `jwks-fetch.ts` inspect + fetch with confirmation, limits, redirect gate.
   - `verifyJwtWithKey` uses local JWK set from that fetch (`jwksConfirmed` required).
   - Forge confirm panel (hostname, sends, receives).
   - CSP connect-src allows loopback HTTP for lab JWKS.
5. **Not done:** Policy editor UI, Team OIDC, DNS-rebinding resolver (browser cannot pin DNS; team mode blocks literal private IPs + allowlist).
6. **Tests:** `npm run test:claimforge` 125 pass; typecheck; lint.
7. **Risks:** Solo mode still allows HTTPS to arbitrary public hosts after confirm (by design). Team SSRF allowlist is API-ready, not a UI.
8. **Working tree:** dirty until push.
9. **Next step only:** P0.7 Confidence/severity/review state completeness across all finding types (not only BOLA/logout). No Team backend.
10. **Next-session prompt:** Continue from repo. Read `docs/agent/HANDOFF.md`. Only implement P0.7 review/confidence consistency + tests. Update handoff before exit.
