# Gap matrix (evidence at remainder+CI repair on `main`)

| ID | Item | Status | Evidence |
|----|------|--------|----------|
| pre | Finding dedup | done | `dedup.ts` + `dedup.test.ts` |
| pre | Lab buckets | done | `src/lib/lab/*`, `migrations/0002_lab_revoke.sql` |
| pre | AuthZ path index | done | `sameObjectHits` in `bola.ts` |
| pre | Worker cancel / latest-job-wins | done | `analyze-async.ts` |
| pre | Threat model | done | `docs/THREAT-MODEL.md` |
| pre | A11y tabs / mobile | done | `desk-nav.ts`, screenshots |
| pre | Parser fuzz | done | `parse.fuzz.test.ts` |
| pre | Security headers | done | `security-headers.ts` |
| P0.1 | Canonical evidence + policy trust | done | Editor + regex validation + `policyApplyDecision` blocks Apply. Role-hierarchy scoring. Request body still cannot prove ownership. |
| P0.2 | Deep redaction + ReportDTO | done | JSON/MD/HTML/PDF from DTO. PDF paginates (kill chain / findings / why / how / loot) with page numbers. Canaries hold. |
| P0.3 | Replay credential boundary | done | `replay-credentials.ts`, `p0-replay-credentials.test.ts` |
| P0.4 | Session/logout model | done | `session.ts` credential-scoped revoke |
| P0.5 | Forge revision machine | done | `forge-revision.ts` |
| P0.6 | JWKS network / SSRF | done | Allowlist is a closed set in every mode; teamMode still blocks RFC1918/ULA/link-local/metadata. UI in Policy. DNS rebinding remains in-browser limited. |
| P0.7 | Review workflow states | done | `review.ts`; Critical requires proven impact |
| P0.8 | Adversarial gate per P0 bug | done | Catalog includes remainder rows (invalid regex, role scoring, allowlist, PDF pages) |
| P1.* | Team / tenant / OIDC | not_started | Remainder + CI repair. Start only if asked. |
| P2–P6 | perf, CI matrix, golden 60 | partial/not_started | CI now typecheck+lint+`npm test`+audit+build. Sandbox-doc tests skip on GitHub checkout. Solo limits 1200 already. |
