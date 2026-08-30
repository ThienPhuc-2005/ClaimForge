# ClaimForge handoff

1. **Repo:** `ThienPhuc-2005/ClaimForge` · branch `main` · **Verified base SHA** `35b2eff` · this session `ef66042`.
2. **Milestone:** v0.9 Core Hardening · **item:** P0.3 Replay credential boundary (this session).
3. **Session goal:** Wipe all source credentials before attaching the selected actor set; mixed Authorization+Cookie+API-Key+CSRF must not mix two sessions. Desk JSON/MD emit ReportDTO only.
4. **Done:**
   - `replay-credentials.ts` — strip Authorization, Proxy-Authorization, Cookie, Set-Cookie, API-Key variants, CSRF headers, token-like headers, workspace extras, secret query/body fields; then attach one actor set.
   - Playbook BOLA/swap/forge replays use the boundary; UI shows masked source + header diff; curl hidden behind details.
   - Desk Export JSON = `renderReportJson(toReportDTO)`; Export MD = redacted markdown. No `requests` / raw HAR on the DTO.
   - Tests: `p0-replay-credentials.test.ts` + playbook updates.
5. **Not done:** Policy editor UI, P0.4 logout multi-session, P0.5 forge Unsigned/Signed/Stale enum, P0.6 JWKS SSRF, Team/OIDC.
6. **Tests:** `npm run test:claimforge` 101 pass; typecheck; lint. See `TEST_STATUS.md`.
7. **Risks:** Masked diff still shows 2-char prefix. Curl copy includes full selected-actor secrets by design. Extra header names have no UI (pass via `ReplayCredentialPolicy.extraHeaderNames`).
8. **Working tree:** sandbox dirty until push.
9. **Next step only:** P0.4 Session/logout — track credentials sent on logout, multi-session, heuristic vs Confirmed. No Team backend.
10. **Next-session prompt:** Continue from repo. Read `docs/agent/HANDOFF.md`. Only implement P0.4 logout/session model + regressions. Update handoff before exit.
