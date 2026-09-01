# ClaimForge threat model and limitations

## What this is

A browser desk that diffs two HTTP captures (Actor A / Actor B) and scores auth bugs: BOLA/IDOR, JWT (`alg=none`, unsigned, RS256/HS* verify), cookie flags, CORS, mass-assignment, and post-logout reuse.

## Trust boundary

- Captures are parsed and scored **in the browser**. They are not uploaded to a ClaimForge server.
- Hosted Grok / PWA shells may inject platform scripts. Do not treat the hosted UI as an air-gapped offline appliance. Self-host or use a local build if that matters for the engagement.
- Optional **JWKS URL** verify is a user-initiated fetch to that URL. Do not point it at untrusted hosts with production tokens in the same tab if that is out of policy.
- Replay curl is generated for **your** interceptor. The desk never sends captured requests at live targets. Replay recipes use **one** actor's bearer; they strip the other actor's `Authorization` and `Cookie`.

## Findings confidence

| Confidence  | Meaning |
|-------------|---------|
| Observation | Header/claim/flag seen. Not a proven exploit. |
| Suspicion   | Pattern that needs policy or a second capture. |
| Confirmed   | Ownership or lab policy evidence (e.g. B 2xx on A's `ownerId`, or 2xx after a 2xx logout on a lab host). |

Heuristics teach a workflow, not a verdict. `alg=none` in a capture does not prove the API accepts it. Absence of findings is not a clean bill of health.

## BOLA / IDOR

Confirmed requires **trusted server-response** ownership (`ownerId` / `userId` on the response, or an inventory list on an identity/private route) plus B 2xx on A's object. Request body, query, and path are never ownership proof. An **unverified JWT `sub` is not a trusted identity and is not an object id**. Analyst-declared actor labels may map to `ownerId`. Public/shared catalog bodies stay Observation.

## CORS

`Access-Control-Allow-Origin: *` plus `Access-Control-Allow-Credentials: true` is **invalid** in the Fetch spec. Browsers fail the CORS check and do **not** expose the credentialed body. ClaimForge does **not** report that pair as a credentialed-response-read bug. Reflected `Origin` + credentials can be.

## Session after logout

A later 2xx with the same bearer is not automatic session-fixation. Confirmed only on lab hosts (`.lab`, `localhost`) **and** when the logout request itself was 2xx. Outside lab the same pattern is Suspicion until revoke policy is evidenced.

## JWT

Inspection is local. Signature status is `unsigned` / `unverified` / `verified` / `invalid`. RS256 needs a PEM or JWKS you supply. Missing `iss`/`aud` is informational, not an exploit. Forge clears a previously signed token when header or payload edits.

## Export

JSON, Markdown, HTML, and PDF exporters consume a redacted **ReportDTO** allowlist only — never raw HAR, JWT compact tokens, cookie values, or AuthZ-diff samples. Nested secret keys, query tokens, and PEM blocks are masked. HTML is escaped; spreadsheet-formula prefixes on wordlists are neutralized. Do not treat export as a full forensic archive of the HAR.

## Performance and workers

AuthZ pairing is indexed by path (O(A+B)), capped, with per-actor request and body limits. A new paste **cancels** in-flight analyze (worker terminate + dropped main-thread yields) so a stale job cannot hang the tab behind a newer capture.

## Victim lab

Vulnerable and Fixed implementations store traffic in separate buckets. Import uses the **current** mode only so mixed-mode captures cannot pollute findings.

Fixed mode signs HS256 with a **server-only** HMAC key (never shipped to the client bundle). Role is taken from the account record, not from JWT claims, so a forged `role=admin` token is rejected even if the caller knows the client code. Logout records the token `jti` (warm-isolate map plus `lab_revoke` when `DATABASE_URL` is set) instead of a process-only `Set` of raw tokens.

## Team mode (P1 — isolation kernel)

Team is **opt-in and self-hosted**. It is not on unless an operator bootstraps a tenant via `npm run team:bootstrap` (env secret + `DATABASE_URL`; no public HTTP, no PGLite fallback). Captures still parse and score in the browser. P1 does **not** upload HAR/HTTP/JWT/cookies.

When Team collab is used, the server may store policy JSON, review-state maps, and a deep-redacted ReportDTO, each row carrying `tenant_id` from a **verified membership context** — never from client-supplied tenant fields.

Grok Better Auth / `VITE_AUTH_ENABLED` is not the Team identity plane and stays off. Platform `requireUserId` is unsafe to call for Team while auth is off and `DATABASE_URL` is set.

Isolation is application-level (`TenantContext` + `WHERE tenant_id = $ctx`) plus composite foreign keys. PostgreSQL RLS is a future defense-in-depth layer, not currently claimed.

In-browser loot/replay export is a local action; the Team server cannot honestly prevent it.

See [P1_TEAM_ISOLATION.md](./P1_TEAM_ISOLATION.md).

## Team mode (P1.2 — customer OIDC + opaque sessions)

Team identity is the operator's IdP, not Grok Better Auth. One confidential client per ClaimForge instance, configured by env. Authorization Code + PKCE S256. Static endpoints; no OIDC discovery.

An attacker must not:

- Turn an unverified JWT (`alg=none`, HS*, wrong iss/aud/nonce/exp) into a `TenantContext`.
- Supply `tenant_id` or `role` in the ID token to switch tenant or escalate.
- JIT-create a `team_member` by presenting a new `sub`.
- Create the first tenant/owner through HTTP, or bootstrap into preview PGLite without `DATABASE_URL`.
- Read a bootstrap secret, client secret, token, or raw OIDC `sub` from CLI output.
- Steal a reusable authorization `code`/`state` (pending is hashed, sealed, single-use; consume deletes the row).
- Grow `team_oidc_pending` without bound by spamming login with random slugs (expired rows are swept; table is capped by evicting oldest; not a slug oracle).
- Read a raw session token or ID/access/refresh token from the database.
- Use a session after the member row is deleted.
- Start Team OIDC on HTTP (or spoof HTTPS via `X-Forwarded-Proto` without a trusted-proxy flag) or without a syntactically valid tenant slug.
- Learn whether a tenant slug exists from login status (valid slugs all 302; existence is fail-closed at callback).
- Point token/JWKS fetch at an unallowlisted or private host (SSRF), or force the RP to buffer an oversized JWKS/token body.
- CSRF-logout a session from another origin.

`CLAIMFORGE_TEAM_TRUST_PROXY` is only safe when a trusted reverse proxy strips or overwrites client-supplied `X-Forwarded-Proto`. Otherwise a caller can spoof HTTPS and receive a `__Host-` cookie on a cleartext request.

The session cookie (`__Host-claimforge-team.session`) may carry the raw opaque token in transit; only its SHA-256 is stored. Logout revokes that local session only — it does not call the IdP. DNS rebinding remains a known P0.6 residual (fetch cannot pin resolved IPs).

P1.3 enforces RBAC from the live `team_member.role` (viewer read-only; `accepted-risk` lead+; members HTTP admin+). It does not persist collab over HTTP (P1.5) or list tenants.

## Limitations

- Incomplete JSON captures used to recurse (`parseHarLike` ↔ `parseRawHttp`) until the stack overflowed. They now fail per actor with a parse error. Parser fuzz lives in CI.
- Heuristics miss bugs that need a live probe (timing, second-order IDOR, CSRF).
- Demo traffic is a lab fixture (`shop.lab`), not a production target.
- Large captures run in a Web Worker; a worker crash rejects every in-flight analyze promise.

## Screenshots

- `docs/screenshots/onboarding.png` — workflow 1–2–3
- `docs/screenshots/desk.png` — Findings after lab capture
- `docs/screenshots/playbook.png` — kill chain + replay pack
- `docs/screenshots/forge.png` — local JWT mutate / sign / verify
- `docs/screenshots/more.png` — More inspect views (ID graph)
- `docs/screenshots/mobile.png` — mobile, results first, actors collapsed

## Production headers

Hosted / `vite preview` responses set Content-Security-Policy (allows the grok.com PWA injector, module workers + `blob:`, and optional JWKS `https:` connect), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy` (camera / microphone / geolocation / payment / usb off), and frame protection (`frame-ancestors 'none'` plus `X-Frame-Options: DENY`). The Vite live-preview server does not apply these so the preview iframe still works.
