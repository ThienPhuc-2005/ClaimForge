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
| P1.0 | Team isolation architecture | done | `docs/P1_TEAM_ISOLATION.md`, ADR-017–031 |
| P1.1 | Tenant isolation kernel | done | `migrations/0003_team_isolation.sql`, `src/lib/team/*`. Frozen WeakMap `TenantContext`; `requireActiveMember`; Team ReportDTO projection. Adversarial tests + `p1-gates.ts`. No HTTP. |
| P1.2 | Customer OIDC + opaque sessions | done | `migrations/0004_team_oidc_sessions.sql`, `src/lib/team/oidc-*.ts`, `session.ts`, `/api/team/oidc/*`, `/api/team/session`. Env IdP, PKCE S256, hashed+sealed pending, tenant-bound opaque sessions, no JIT. Operator CLI `npm run team:bootstrap`. ADR-034/035. Not Grok Better Auth. Merged PR #2 squash `6de17a4`. |
| P1.3 | RBAC on Team APIs | done | Live `team_member.role`. Viewer read-only. `accepted-risk` lead+. Admin+ `/api/team/members`. ADR-036. Merged PR #3 squash `4cefe02`. A3 lab 36/36 (Chrome+Firefox+Postgres). Server cannot claim in-browser export control. |
| P1.4 | Append-only audit | done | `migrations/0005_team_audit.sql`, `src/lib/team/audit.ts`, `GET /api/team/audit`. Omit IP/UA (ADR-023). Live member actor. Member delete does not erase rows. ADR-037. Squash-merged in PR #6 `1be6d07`. A-lab Chromium+Postgres 27/27 (sandbox-only). |
| P1.5 | Collab HTTP for policy/review/ReportDTO | done | Session-bound workspaces + collab HTTP. Kernel persist/RBAC. ADR-038. Squash-merged in PR #6 `1be6d07`. A-lab Chromium+Postgres 27/27 (sandbox-only). |
| P1.6 | Team UI | done | More → Team over the session. ADR-039. Squash-merged in PR #6 `1be6d07`. A-lab Chromium+Postgres 27/27 (sandbox-only). |
| P1.7 | Postgres RLS | done | `0006_team_rls.sql` FORCE RLS + kernel GUC. ADR-040. Squash-merged in PR #7 `9cbd88d`. Dedicated Postgres test (non-superuser). A-lab Chromium+Postgres 31/31 (sandbox-only; missing GUC hides workspaces). |
| P2.1 | BFLA detection | done | `bfla.ts` + `p2-bfla.test.ts`. Non-priv actor 2xx on admin function. Enforcement = 403 only (not 401). `is_admin` honored. Verb-tampering caught (per-template). Self routes excluded. Confirmed = verified non-priv role + 403 contrast; else Suspicion. ADR-041. |
| P2.2 | CSRF detection | done | `csrf.ts` + `p2-csrf.test.ts`. Cookie-auth state change, no anti-CSRF token. Never Confirmed (passive). SameSite=None → Suspicion; no-attribute/unobserved → Observation. Token matched by name not value. Bearer excluded. Analytics cookies + X-Requested-With not counted. ADR-041. |
| P2.3 | Refresh-token reuse | done | `refresh.ts` + `p2-refresh.test.ts`. Rotated token accepted again. Always Suspicion (RFC 9700 grace window is legitimate). Scoped to token endpoints. snake_case + camelCase + header/cookie tokens. ADR-041. |
| P2.4 | OpenAPI/Swagger coverage | done | `spec.ts` + `p2-spec.test.ts`. JSON-only offline surface diff. Regex path matching (non-numeric params). Host-scoped (drops third-party). Covered = <400 seen. Untested + shadow findings. `specRaw` threaded through worker/store/UI. ADR-042. |
| P2.5 | Scale + truncation visibility | done | `limits.ts` 24MB / 4000 per actor. `Workspace.truncation` + `CAPTURE_TRUNCATED` finding + header banner. No silent drops. `p2-scale-truncation.test.ts`. ADR-043. |
| P2.* | Adversarial review of P2 | done | Attack→verify workflow per family; real FPs/FNs fixed with regression tests before commit. `p2-gates.ts` + `p2-adversarial-gate.test.ts`. |
| P2.next | Plain destructive-on-object BFLA (`DELETE /users/{id}`) | not_started | Deliberately deferred: needs ownership context to avoid flagging self-account deletion. Documented in KNOWN_ISSUES. |
| P1.*-capture | Encrypted capture share | not_started | Requires new threat model. Not P1. |
| P2–P6 | perf, CI matrix, golden 60 | partial/not_started | CI now typecheck+lint+`npm test`+audit+build. Sandbox-doc tests skip on GitHub checkout. Solo limits 1200 already. CI is not merge-enforced until a ruleset exists (ADR-029). |
