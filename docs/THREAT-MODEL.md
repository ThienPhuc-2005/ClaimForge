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

Confirmed requires body ownership (`ownerId` / `userId`) or an actor inventory list. An **unverified JWT `sub` is not an object id**. A numeric `sub` that collides with `/resource/{id}` is not Confirmed. Public/shared catalog bodies stay Observation.

## CORS

`Access-Control-Allow-Origin: *` plus `Access-Control-Allow-Credentials: true` is **invalid** in the Fetch spec. Browsers fail the CORS check and do **not** expose the credentialed body. ClaimForge does **not** report that pair as a credentialed-response-read bug. Reflected `Origin` + credentials can be.

## Session after logout

A later 2xx with the same bearer is not automatic session-fixation. Confirmed only on lab hosts (`.lab`, `localhost`) **and** when the logout request itself was 2xx. Outside lab the same pattern is Suspicion until revoke policy is evidenced.

## JWT

Inspection is local. Signature status is `unsigned` / `unverified` / `verified` / `invalid`. RS256 needs a PEM or JWKS you supply. Missing `iss`/`aud` is informational, not an exploit. Forge clears a previously signed token when header or payload edits.

## Export

JSON and Markdown exports redact JWT compact tokens, bearer/basic, cookie values, and password/secret JSON fields — including those nested in AuthZ-diff samples and finding evidence. Do not treat export as a full forensic archive of the HAR.

## Performance and workers

AuthZ pairing is indexed by path (O(A+B)), capped, with per-actor request and body limits. A new paste **cancels** in-flight analyze (worker terminate + dropped main-thread yields) so a stale job cannot hang the tab behind a newer capture.

## Victim lab

Vulnerable and Fixed implementations store traffic in separate buckets. Import uses the **current** mode only so mixed-mode captures cannot pollute findings.

## Limitations

- Incomplete JSON captures used to recurse (`parseHarLike` ↔ `parseRawHttp`) until the stack overflowed. They now fail per actor with a parse error. Parser fuzz lives in CI.
- Heuristics miss bugs that need a live probe (timing, second-order IDOR, CSRF).
- Demo traffic is a lab fixture (`shop.lab`), not a production target.
- Large captures run in a Web Worker; a worker crash rejects every in-flight analyze promise.

## Screenshots

- `docs/screenshots/desk.png` — findings desk
- `docs/screenshots/mobile.png` — mobile, results first, actors collapsed
- `docs/screenshots/onboarding.png` — workflow 1–2–3
