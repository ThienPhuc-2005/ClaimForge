/**
 * P0.8 catalog: every P0.1–P0.7 bug has a test that would fail if the fix is reverted.
 * `before` is the broken engine; `after` is the required behavior.
 */
export const P0_ITEMS = ["P0.1", "P0.2", "P0.3", "P0.4", "P0.5", "P0.6", "P0.7"] as const;
export type P0Item = (typeof P0_ITEMS)[number];

export interface P0Gate {
  id: string;
  p0: P0Item;
  bug: string;
  before: string;
  after: string;
  evidenceTest: string;
}

export const P0_GATES: P0Gate[] = [
  {
    id: "P0.1-request-body-owner",
    p0: "P0.1",
    bug: "Client-supplied request body ownerId treated as server ownership",
    before: "Confirmed Critical BOLA from POST ownerId",
    after: "Request body cannot confirm BOLA",
    evidenceTest: "p0-trust-boundary.test.ts:request body ownerId cannot create confirmed BOLA",
  },
  {
    id: "P0.1-request-query-owner",
    p0: "P0.1",
    bug: "Query ownerId treated as server ownership",
    before: "Confirmed BOLA from ?ownerId=",
    after: "Request query cannot confirm BOLA",
    evidenceTest: "p0-trust-boundary.test.ts:request query ownerId cannot create confirmed BOLA",
  },
  {
    id: "P0.1-unverified-jwt-sub",
    p0: "P0.1",
    bug: "Unverified JWT sub used as trusted identity / object id",
    before: "Unsigned sub colliding with /resource/{id} confirms BOLA",
    after: "Unverified JWT sub is never trusted ownership",
    evidenceTest: "p0-trust-boundary.test.ts:unverified JWT sub colliding with object id cannot confirm BOLA",
  },
  {
    id: "P0.1-path-owner",
    p0: "P0.1",
    bug: "Path segment treated as owner proof",
    before: "GET /users/{alice}/invoices/{id} 2xx confirms BOLA",
    after: "Request path is never ownership proof",
    evidenceTest: "p0-adversarial-gate.test.ts:GATE P0.1 path segment is not ownership",
  },
  {
    id: "P0.2-allowlist-dto",
    p0: "P0.2",
    bug: "Exporters serialized raw HAR, JWT payload, cookie values",
    before: "JSON export contained aRaw / jwt.payload / cookie.value",
    after: "Exporters consume ReportDTO allowlist only",
    evidenceTest: "p0-report-dto.test.ts:ReportDTO is allowlist: no raw capture, samples, jwt payload, or cookie values",
  },
  {
    id: "P0.2-canary-secrets",
    p0: "P0.2",
    bug: "Planted secrets survived JSON/MD/HTML/PDF",
    before: "Canary token leaked in every export format",
    after: "Canary is redacted in JSON, MD, HTML, and PDF",
    evidenceTest: "p0-report-dto.test.ts:canary secrets planted in every slot do not survive JSON/MD/HTML/PDF",
  },
  {
    id: "P0.2-html-xss",
    p0: "P0.2",
    bug: "Finding title/why rendered as HTML",
    before: "<script> in title executed in HTML export",
    after: "HTML escapes markup; markdown strips fence breakers",
    evidenceTest: "p0-report-dto.test.ts:HTML escapes markup; markdown strips fence breakers; formulas prefixed",
  },
  {
    id: "P0.2-formula-wordlist",
    p0: "P0.2",
    bug: "Wordlist cells started with = + @ (spreadsheet formula injection)",
    before: "Markdown wordlist contained a leading =HYPERLINK",
    after: "Wordlist entries are formula-neutralized",
    evidenceTest: "p0-adversarial-gate.test.ts:GATE P0.2 wordlist formulas are neutralized in markdown",
  },
  {
    id: "P0.3-mixed-sessions",
    p0: "P0.3",
    bug: "Replay kept source Authorization/Cookie/API-Key/CSRF while attaching the other actor",
    before: "curl mixed Alice cookie with Bob bearer",
    after: "Source credentials wiped, then one actor set attached",
    evidenceTest: "p0-replay-credentials.test.ts:P0.3 mixed Authorization+Cookie+API-Key+CSRF cannot mix two sessions",
  },
  {
    id: "P0.3-query-and-csrf-body",
    p0: "P0.3",
    bug: "Query access_token and body csrf survived the wipe",
    before: "Replay URL still had Alice access_token",
    after: "Query tokens and csrf body fields are stripped",
    evidenceTest: "p0-replay-credentials.test.ts:strip removes every source credential including query and csrf body",
  },
  {
    id: "P0.3-extra-header-policy",
    p0: "P0.3",
    bug: "Custom session header was not in the credential class",
    before: "X-Corp-Session from A remained after attaching B",
    after: "Policy extra headers are wiped then replaced",
    evidenceTest: "p0-replay-credentials.test.ts:workspace extra credential header is wiped then replaced",
  },
  {
    id: "P0.4-sibling-session",
    p0: "P0.4",
    bug: "Logout of one bearer revoked a sibling cookie/bearer on the same actor",
    before: "One logout confirmed leftover for a different credential",
    after: "Only credentials on the logout request are revoked",
    evidenceTest: "p0-session-logout.test.ts:logout one session; sibling bearer+cookie still valid is not a finding for the sibling",
  },
  {
    id: "P0.4-unauthenticated-logout",
    p0: "P0.4",
    bug: "Logout without credentials confirmed leftover sessions",
    before: "GET /logout 200 with no cookie confirmed later bearer 2xx",
    after: "Unauthenticated logout does not confirm leftover sessions",
    evidenceTest: "p0-session-logout.test.ts:logout with no credential does not confirm leftover sessions",
  },
  {
    id: "P0.4-public-logout-path",
    p0: "P0.4",
    bug: "Public /docs/logout counted as session revoke",
    before: "Docs page named logout confirmed leftover /api/me",
    after: "Public path named logout is not an analysis target",
    evidenceTest: "p0-session-logout.test.ts:public path named logout is not a session-logout analysis target",
  },
  {
    id: "P0.4-rotated-token",
    p0: "P0.4",
    bug: "Logout of old bearer also revoked a later rotated token",
    before: "New access token after refresh was marked leftover",
    after: "Only the values on the logout request are revoked",
    evidenceTest: "p0-session-logout.test.ts:cookie+bearer logout only revokes those values, not a later rotated token",
  },
  {
    id: "P0.5-unsigned-copy-denied",
    p0: "P0.5",
    bug: "Unsigned draft could be copied as a valid signed token",
    before: "canCopySignedAsValid true on a fresh machine",
    after: "Unsigned draft cannot copy as signed-valid",
    evidenceTest: "p0-forge-revision.test.ts:fresh machine is unsigned-draft; signed token copy is denied",
  },
  {
    id: "P0.5-stale-after-edit",
    p0: "P0.5",
    bug: "Editing header/payload/alg after sign still allowed copy of the old signature",
    before: "Signed copy stayed valid after draft mutation",
    after: "Any listed field change stales output and blocks copy",
    evidenceTest: "p0-forge-revision.test.ts:changing header after sign makes output stale and blocks signed copy",
  },
  {
    id: "P0.6-http-non-loopback",
    p0: "P0.6",
    bug: "HTTP JWKS to arbitrary hosts (SSRF)",
    before: "http://evil.example/jwks inspected as ok",
    after: "HTTP only on loopback; HTTPS otherwise",
    evidenceTest: "p0-jwks-fetch.test.ts:HTTPS ok; HTTP only loopback",
  },
  {
    id: "P0.6-unconfirmed-fetch",
    p0: "P0.6",
    bug: "JWKS fetched without analyst confirmation",
    before: "fetch() ran on paste",
    after: "Unconfirmed fetch is denied and does not call fetch",
    evidenceTest: "p0-jwks-fetch.test.ts:unconfirmed fetch is denied and does not call fetch",
  },
  {
    id: "P0.6-metadata-userinfo",
    p0: "P0.6",
    bug: "JWKS URL could target metadata or embed userinfo",
    before: "169.254.169.254 and user:pass@host were allowed",
    after: "Metadata and userinfo are blocked",
    evidenceTest: "p0-jwks-fetch.test.ts:metadata and userinfo blocked",
  },
  {
    id: "P0.6-redirect-revalidate",
    p0: "P0.6",
    bug: "302 to http://evil.example followed without revalidation",
    before: "Redirect hop skipped inspectJwksUrl",
    after: "Each hop is revalidated; HTTP hop denied",
    evidenceTest: "p0-jwks-fetch.test.ts:redirect is revalidated; HTTP hop denied",
  },
  {
    id: "P0.6-credentials-omit",
    p0: "P0.6",
    bug: "JWKS fetch sent cookies (credentials:include)",
    before: "Browser cookies attached to issuer.example",
    after: "fetch uses credentials=omit and redirect=manual",
    evidenceTest: "p0-adversarial-gate.test.ts:GATE P0.6 fetch omits credentials and does not follow redirects",
  },
  {
    id: "P0.6-audit-no-jwk",
    p0: "P0.6",
    bug: "Audit log stored JWK n/e material",
    before: "audit JSON contained RSA n/e",
    after: "Audit is hostname/status/bytes only",
    evidenceTest: "p0-adversarial-gate.test.ts:GATE P0.6 audit must not contain JWK material",
  },
  {
    id: "P0.7-type-name-not-critical",
    p0: "P0.7",
    bug: "Finding type name (JWT/cookie/BOLA) self-promoted to Critical",
    before: "alg=none was Confirmed Critical",
    after: "Observation/Suspicion never Critical; type name is not impact",
    evidenceTest: "p0-review-state.test.ts:observation and suspicion cannot be Critical; type name is not impact",
  },
  {
    id: "P0.7-jwt-none-observation",
    p0: "P0.7",
    bug: "JWT alg=none in a capture treated as a proven exploit",
    before: "Unsigned JWT finding was Confirmed",
    after: "alg=none stays Observation, never Critical",
    evidenceTest: "p0-review-state.test.ts:JWT alg=none is Observation, never Confirmed or Critical",
  },
  {
    id: "P0.7-unproven-idor",
    p0: "P0.7",
    bug: "Same-object 2xx without ownership called Confirmed BOLA",
    before: "Both actors 200 on /items/77 without ownerId was Critical",
    after: "Unproven same-object 2xx is Suspicion, not Critical",
    evidenceTest: "p0-review-state.test.ts:same-object 2xx without ownership is Suspicion medium, not Confirmed Critical",
  },
  {
    id: "P0.7-review-not-confidence",
    p0: "P0.7",
    bug: "Analyst reviewState=confirmed raised engine confidence",
    before: "Overlay mutated confidence/severity",
    after: "Review overlay does not change engine confidence",
    evidenceTest: "p0-review-state.test.ts:analyst review overlay does not change engine confidence",
  },
  {
    id: "P0.7-cors-star-not-exploit",
    p0: "P0.7",
    bug: "ACAO * + credentials reported as Confirmed credentialed-read",
    before: "Invalid CORS pair was Critical Confirmed",
    after: "Star+credentials is not a Confirmed Critical finding",
    evidenceTest: "p0-adversarial-gate.test.ts:GATE P0.7 CORS star+credentials is not Confirmed Critical",
  },
];

export function gatesFor(p0: P0Item): P0Gate[] {
  return P0_GATES.filter((g) => g.p0 === p0);
}
