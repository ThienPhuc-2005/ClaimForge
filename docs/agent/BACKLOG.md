# Gap matrix (evidence at HEAD `35b2eff` + this session)

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
| P0.1 | Canonical evidence + policy trust | done (slice) | `policy.ts`, `evidence.ts`, `p0-trust-boundary.test.ts`. No policy editor UI. |
| P0.2 | Deep redaction + ReportDTO | done (slice) | `report-dto.ts`, JSON/MD/HTML/PDF; canaries. PDF is text-only. Desk JSON/MD now DTO-only. |
| P0.3 | Replay credential boundary | done (slice) | `replay-credentials.ts`, `p0-replay-credentials.test.ts`, playbook + PlaybookView |
| P0.4 | Session/logout model | done (slice) | `session.ts` credential-scoped revoke; `p0-session-logout.test.ts` |
| P0.5 | Forge revision machine | partial | forge clears signed output; no explicit Unsigned/Signed/Stale enum |
| P0.6 | JWKS network / SSRF | missing | user-initiated fetch only |
| P0.7 | Review workflow states | partial | confidence classes exist; reviewState on BOLA findings |
| P0.8 | Adversarial gate per P0 bug | partial | P0.1–P0.3 tests exist |
| P1.* | Team / tenant / OIDC | not_started | spec forbids until P0 green |
| P2–P6 | perf, CI matrix, golden 60 | partial/not_started | solo limits 1200 already |
