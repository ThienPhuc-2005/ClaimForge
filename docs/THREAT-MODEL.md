# ClaimForge threat model and limitations

## What this is

A browser desk that diffs two HTTP captures (Actor A / Actor B) and scores auth bugs: BOLA/IDOR, JWT (`alg=none`, unsigned, RS256/HS* verify), cookie flags, CORS, mass-assignment, and post-logout reuse.

## Trust boundary

- Captures are parsed and scored **in the browser**. They are not uploaded to a ClaimForge server.
- Hosted Grok / PWA shells may inject platform scripts. Do not treat the hosted UI as an air-gapped offline appliance. Self-host or use a local build if that matters for the engagement.
- Optional **JWKS URL** verify is a user-initiated fetch to that URL. Do not point it at untrusted hosts with production tokens in the same tab if that is out of policy.
- Replay curl is generated for **your** interceptor. The desk never sends captured requests at live targets.

## Findings confidence

| Confidence  | Meaning |
|-------------|---------|
| Observation | Header/claim/flag seen. Not a proven exploit. |
| Suspicion   | Pattern that needs policy or a second capture. |
| Confirmed   | Ownership or lab policy evidence (e.g. B 2xx on A's `ownerId`, or 2xx after a 2xx logout on a lab host). |

## CORS

`Access-Control-Allow-Origin: *` plus `Access-Control-Allow-Credentials: true` is **invalid** in the Fetch spec. Browsers fail the CORS check and do **not** expose the credentialed body. ClaimForge does **not** report that pair as a credentialed-response-read bug. Reflected `Origin` + credentials can be.

## Session after logout

A later 2xx with the same bearer is not automatic session-fixation. Confirmed only on lab hosts (`.lab`, `localhost`) **and** when the logout request itself was 2xx. Outside lab the same pattern is Suspicion until revoke policy is evidenced.

## JWT

Inspection is local. Signature status is `unsigned` / `unverified` / `verified` / `invalid`. RS256 needs a PEM or JWKS you supply. Missing `iss`/`aud` is informational, not an exploit.

## Limitations

- Incomplete JSON captures used to recurse (`parseHarLike` ↔ `parseRawHttp`) until the stack overflowed. They now fail per actor with a parse error.
- Heuristics miss bugs that need a live probe (timing, second-order IDOR, CSRF).
- Demo traffic is a lab fixture (`shop.lab`), not a production target.
- Large captures run in a Web Worker; a worker crash rejects every in-flight analyze promise.

## Screenshots

- `public/screenshots/desk.png` — findings desk
- `public/screenshots/mobile.png` — mobile, results first, actors collapsed
