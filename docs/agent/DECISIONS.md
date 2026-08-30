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

BOLA replay used to keep leftover Cookie when swapping Bearer. P0.3 strips every credential-class header (Authorization, Proxy-Authorization, Cookie, Set-Cookie, API-Key variants, CSRF, token-like, workspace extras) plus secret query/body fields, then attaches only `extractActorCredentials` for the selected actor. Mixing Cookie+Bearer from the *same* actor is allowed; mixing two actors is not. UI diffs are masked (2-char prefix). Curl copy is the lab artifact and keeps the selected set in full.

## ADR-007 — Logout revokes only credentials on that request

Prior logic marked every token ever seen for the actor as revoked on any logout. P0.4 treats each bearer, session cookie, and API-key as its own session. Sibling device cookies/bearers stay live. Public routes whose path contains "logout" and logout requests with no credentials are not Confirmed. Lab + 2xx logout + same credential 2xx afterwards remains Confirmed.
