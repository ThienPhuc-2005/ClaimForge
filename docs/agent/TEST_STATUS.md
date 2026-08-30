# Test status

- **When:** P1.2-R1 on `feat/p1.2-oidc-sessions` (draft PR #2, not merged). `main` still P1.1 squash `fa21439` / docs `f1a0771`.
- **Branch:** `feat/p1.2-oidc-sessions`
- **Compared against:** `f1a0771` (`origin/main`)
- **Commands (local, this branch; GitHub Actions on this SHA is evidence once the draft PR workflow runs — ADR-016 / ADR-029):**
  - `npm test` → **455 tests / 451 pass / 4 skip / 0 fail**
  - `npm run typecheck` → pass
  - `npm run lint` → pass
  - `npm run audit:deps` → 0 vulnerabilities (`--audit-level=high`)
  - `npm run build` → pass
- **CI workflow:** typecheck + lint + `npm test` + `audit:deps` + `build`. Materializes `.grok/app-env.json` (auth-off). Sandbox-doc tests skip when `AGENTS.md` / `.grok/skills` are absent.
- **CI vs merge:** `main` has no branch protection. Green Actions is evidence, not a merge gate. Do not merge P1.2 from the implementing session.
- **Browser:** no Team UI in P1.2 (routes are API-only).
