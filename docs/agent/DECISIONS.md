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

BOLA replay used to keep leftover Cookie when swapping Bearer. P0.3 strips every credential-class header, then attaches only the selected actor set. Mixing two actors is not allowed.

## ADR-007 — Logout revokes only credentials on that request

Each bearer, session cookie, and API-key is its own session. Sibling devices stay live. Public logout-named routes and unauthenticated logout are not Confirmed.

## ADR-008 — Forge signed output is revision-bound

A signed compact JWT is valid to copy only while `signedAtRevision === revision`. Any change to header, payload, alg, HMAC secret, public PEM, JWKS URL, kid, issuer, or audience bumps revision and labels the previous signature Stale. The unsigned draft stays copyable.
