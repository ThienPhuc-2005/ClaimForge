# ClaimForge handoff

1. **Repo:** `ThienPhuc-2005/ClaimForge` · branch `main` · session base `11c2051`. Push will move HEAD.
2. **Milestone:** v0.9 Core Hardening · **item:** P0.2 Canonical ReportDTO (this session).
3. **Session goal:** ReportDTO allowlist; exporters JSON/MD/HTML/PDF only see redacted DTO; canary tests.
4. **Done:**
   - `toReportDTO` / `buildReport` — no aRaw, requests, jwt payload/raw, cookie values, diff samples.
   - Renderers: JSON, Markdown, HTML (escaped), minimal PDF 1.4.
   - CWE/OWASP + CVSS draft on findings; redaction preview field.
   - Canaries in `p0-report-dto.test.ts`.
5. **Not done:** Policy editor, P0.3 replay credential matrix, Team/OIDC. PDF is a text dump not a paginated layout.
6. **Tests:** `npm run test:claimforge` 96 pass; typecheck; lint. See `TEST_STATUS.md`.
7. **Risks:** CVSS is always draft. Custom workspace secret-key lists not yet a UI. PDF has no embedded fonts beyond Helvetica.
8. **Working tree:** sandbox dirty until push.
9. **Next step only:** P0.3 Replay credential boundary — strip all source credentials before attaching the selected actor set; UI source/diff without full secrets. No Team backend.
10. **Next-session prompt:** Continue from repo. Read `docs/agent/HANDOFF.md`. Only implement P0.3 replay credential wipe + tests for mixed Authorization/Cookie/API-Key/CSRF. Update handoff before exit.
