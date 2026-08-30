# Session log

## 2026-08-30 — P0.3 replay credential boundary

- `stripSourceCredentials` + `attachActorCredentials` + mixed-header adversarial tests.
- Playbook BOLA/swap/forge go through the boundary. UI: masked diff, curl behind details.
- Desk JSON/MD serialize ReportDTO only (`renderReportJson(toReportDTO)` / `engagementMarkdown`).
- 101 tests green. Next: P0.4 logout/session.

## 2026-08-30 — P0.2 ReportDTO

- Allowlist ReportDTO; exporters no longer emit raw captures or JWT payload.
- Canary secrets in findings, loot, replay, graph, jwt, cookies, diffs, wordlists do not survive JSON/MD/HTML/PDF.
- HTML escape + formula neutralization tests.
- Next: P0.3 replay credentials.

## 2026-08-30 — P0.1 trust boundary + agent docs bootstrap

- Audited GitHub `ThienPhuc-2005/ClaimForge` at `b7665b7`. Spec file was not in repo (provided in chat).
- Did not rewrite existing BOLA/dedup/worker/lab.
- Implemented policy/evidence/hash/versions; tightened `ownedObjects`; analysis envelope versions+hashes.
- Tests: 92 green. typecheck/lint green.
- Created `docs/agent/*`.
- Next: P0.2 ReportDTO.
