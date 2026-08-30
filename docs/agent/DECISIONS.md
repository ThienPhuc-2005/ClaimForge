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

No PDF library in the tree. P0.2 ships a PDF 1.4 Helvetica renderer for canaries and offline share. Remainder paginates (~46 lines/page) and includes kill chain, findings, why, reason codes, evidence, and loot. Layout quality remains P3.

## ADR-006 — Replay wipes source credentials then attaches one actor set

P0.3 strips credential-class headers then attaches only the selected actor set.

## ADR-007 — Logout revokes only credentials on that request

Each bearer, session cookie, and API-key is its own session. Sibling devices stay live.

## ADR-008 — Forge signed output is revision-bound

A signed compact JWT is valid to copy only while `signedAtRevision === revision`.

## ADR-009 — JWKS fetch is confirmed, allowlisted, and never uses createRemoteJWKSet

P0.6 fetches the JWKS document with `credentials:omit`, `redirect:manual`, HTTPS (HTTP loopback only), size/timeout/content-type gates, and `jwksConfirmed`. Audit stores hostname/status/bytes, never tokens or JWK material. A non-empty hostname allowlist is a closed exact-hostname set in every mode. Team mode additionally blocks private/link-local/metadata.

## ADR-010 — Engine confidence is not analyst review

P0.7 keeps two orthogonal fields on every finding:

- `confidence` (Observation / Suspicion / Confirmed) is deterministic, produced by the rule engine, and cannot be edited.
- `reviewState` is the analyst workflow (`new` → `needs-evidence` | `confirmed` | `rejected` | `accepted-risk` → `fixed` → retest).

Severity never becomes Critical from a finding type name. Observation and Suspicion cap at High. Confirmed Critical requires proven impact (`CROSS_ACTOR_2XX` + `SERVER_OWNERSHIP_PROOF`). Analyst review overlays persist by fingerprint and survive re-analysis without changing engine confidence.

## ADR-011 — P0.8 is a fail-then-pass catalog, not a rewrite

Each P0.1–P0.7 bug is a row in `p0-gates.ts` with `before` (broken engine) and `after` (required behavior), pointing at a test that would fail if the fix is reverted. New gaps (path-as-owner, wordlist formulas, JWKS `credentials:omit`, audit JWK material, CORS `*`+credentials through analyze) live in `p0-adversarial-gate.test.ts`. Remainder rows cover invalid regex, role-hierarchy scoring, allowlist closed set, and PDF pagination.

## ADR-012 — Policy editor re-runs one engine, does not rewrite the desk

P0.1 remainder is a More-view editor. Public/shared/private/identity patterns, ownership fields, success/deny statuses, JWT iss/aud, logout paths, role hierarchy, and JWKS allowlist all feed the same `AnalysisPolicy`. Apply bumps version when content changes, re-runs analyze, and diffs findings by fingerprint (added / removed / changed). Extra ownership field names (e.g. `tenantId`) are allowed; request body/query/path still cannot prove ownership. Invalid regex is reported and blocks Apply. No Team backend. Primary tabs unchanged.

## ADR-013 — Role hierarchy scores only when declared

Empty `roleHierarchy` never escalates (demo mass-assign stays Observation). When a tree is declared: JWT privileged-role findings fire only for tree parents; a mass-assign that writes a strictly superior role is Confirmed `ROLE_ESCALATION`, severity capped below Critical (no cross-actor ownership proof).

## ADR-014 — JWKS allowlist is a closed set in every mode

A non-empty `jwksHostnameAllowlist` is exact-hostname match (trailing-dot normalized, no subdomain inheritance) for every hop, including solo. Empty list stays open in solo. Team mode still blocks RFC1918 / ULA / link-local / metadata even if listed; loopback in team mode requires allowlist membership. Fetch stays `credentials:omit` + `redirect:manual`.

## ADR-015 — CI required gates are typecheck, lint, all first-party tests, audit, build

`.github/workflows/ci.yml` runs `npm run typecheck`, `lint`, `npm test` (quoted `src/**/*.test.ts` + `scripts/*.test.mjs`), `npm run audit:deps` (`npm audit --audit-level=high`), and `npm run build`. Platform chrome unit tests isolate from product `site.json` / `public/og.jpg`. Auth migration glob must not include `migrations/auth/0001_auth.sql`; product SQL in `migrations/` is allowed. Sandbox-only tripwires that read gitignored `AGENTS.md` / `.grok/skills` skip when those files are absent. CI materializes `.grok/app-env.json` (`VITE_AUTH_ENABLED=false`) because `.grok/` is gitignored and ClaimForge is auth-off.

## ADR-016 — Agent docs record git HEAD, not a sibling remainder SHA

`HANDOFF.md` and `TEST_STATUS.md` must name `git rev-parse HEAD` and the working tree (including untracked files). A feature parent may be listed separately. Claiming tests green requires the GitHub Actions run on that HEAD, not only a local `npm test`.
