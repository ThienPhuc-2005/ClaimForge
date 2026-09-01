# Test status

- **When:** P1.3-R1 extra RBAC HTTP cases on `feat/p1.3-rbac-http` (draft, not merged). Parent: `main` P1.2 squash `6de17a4`.
- **Branch:** `feat/p1.3-rbac-http`
- **Compared against:** `6de17a4` (`origin/main`)
- **Commands (local, this branch; GitHub Actions on this SHA is evidence once the draft PR workflow runs — ADR-016 / ADR-029):**
  - `npm test` → **482 tests / 478 pass / 4 skip / 0 fail** on a GitHub checkout (sandbox-doc tests skip without `AGENTS.md` / `.grok/skills`). Local sandbox with those files: 482 pass / 0 skip.
  - `npm run typecheck` → pass (this SHA)
  - `npm run lint` → pass (this SHA)
  - `npm run audit:deps` → 0 high
  - `npm run build` → pass (this SHA)
- **CI workflow:** typecheck + lint + `npm test` + `audit:deps` + `build`. Materializes `.grok/app-env.json` (auth-off). Sandbox-doc tests skip when `AGENTS.md` / `.grok/skills` are absent.
- **CI vs merge:** `main` has no branch protection. Green Actions is evidence, not a merge gate. Do not merge P1.3 from the implementing session.
- **Browser:** no Team UI in P1.3 (members routes are API-only).
