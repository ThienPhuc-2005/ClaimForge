# Decisions

## ADR-001 — Analyst labels are trusted identity in Solo mode

Unsigned/unverified JWTs are common in lab HAR. Spec allows analyst-declared actor mapping as a trusted identity source. Default policy therefore treats `aLabel`/`bLabel` as trusted owner names when matching response `ownerId`/`userId`. Unverified JWT `sub` is never trusted.

## ADR-002 — Request body is never ownership proof

`ownerLinks` on `requestBody` (and query/path) cannot populate `ownedObjects`. Only response JSON owner fields (allowlisted) and inventory arrays on identity/private routes.

## ADR-003 — JWT subject values are never object ids

Inventory and owner-object ids that equal any captured JWT subject (even unverified) are skipped so `sub`/`userId` colliding with `/resource/{id}` cannot confirm BOLA.

## ADR-004 — Exporters only accept ReportDTO

`exportReportJson` / markdown / html / pdf map from `toReportDTO`. Diff samples, jwt payload, cookie values, and raw HAR are dropped rather than redacted-in-place.

## ADR-005 — PDF is a generated text PDF

No PDF library in the tree. P0.2 ships a PDF 1.4 Helvetica text dump for canaries and offline share. Layout quality is P3.

## ADR-006 — Replay wipes source credentials then attaches one actor set

P0.3 strips credential-class headers then attaches only the selected actor set.

## ADR-007 — Logout revokes only credentials on that request

Each bearer, session cookie, and API-key is its own session. Sibling devices stay live.

## ADR-008 — Forge signed output is revision-bound

A signed compact JWT is valid to copy only while `signedAtRevision === revision`.

## ADR-009 — JWKS fetch is confirmed, allowlisted, and never uses createRemoteJWKSet

P0.6 fetches the JWKS document with `credentials:omit`, `redirect:manual`, HTTPS (HTTP loopback only), size/timeout/content-type gates, and `jwksConfirmed`. Audit stores hostname/status/bytes, never tokens or JWK material. Team mode blocks private/link-local/metadata and requires a hostname allowlist.

## ADR-010 — Engine confidence is not analyst review

P0.7 keeps two orthogonal fields on every finding:

- `confidence` (Observation / Suspicion / Confirmed) is deterministic, produced by the rule engine, and cannot be edited.
- `reviewState` is the analyst workflow (`new` → `needs-evidence` | `confirmed` | `rejected` | `accepted-risk` → `fixed` → retest).

Severity never becomes Critical from a finding type name. Observation and Suspicion cap at High. Confirmed Critical requires proven impact (`CROSS_ACTOR_2XX` + `SERVER_OWNERSHIP_PROOF`). Analyst review overlays persist by fingerprint and survive re-analysis without changing engine confidence.

## ADR-011 — P0.8 is a fail-then-pass catalog, not a rewrite

Each P0.1–P0.7 bug is a row in `p0-gates.ts` with `before` (broken engine) and `after` (required behavior), pointing at a test that would fail if the fix is reverted. New gaps (path-as-owner, wordlist formulas, JWKS `credentials:omit`, audit JWK material, CORS `*`+credentials through analyze) live in `p0-adversarial-gate.test.ts`. Product code is unchanged.

## ADR-012 — Policy editor re-runs one engine, does not rewrite the desk

P0.1 remainder is a More-view editor. Public/shared/private/identity patterns, ownership fields, success/deny statuses, JWT iss/aud, logout paths, and role hierarchy all feed the same `AnalysisPolicy` already used by BOLA, session, and ownership. Apply bumps version when content changes, re-runs analyze, and diffs findings by fingerprint (added / removed / changed). Extra ownership field names (e.g. `tenantId`) are allowed; request body/query/path still cannot prove ownership. No Team backend. Primary tabs unchanged.
