# Test status

- **When:** P1.1 squash on `main` (`fa21439`)
- **Branch:** `main`
- **Compared against:** `f1ed912` (pre-P1.1 `main`)
- **Commands (GitHub Actions run 24 on `fa21439`):**
  - `npm test` → **418 tests / 414 pass / 4 skip / 0 fail**
  - `npm run typecheck` → pass
  - `npm run lint` → pass
  - `npm run audit:deps` → 0 vulnerabilities (`--audit-level=high`)
  - `npm run build` → pass
- **CI workflow:** typecheck + lint + `npm test` + `audit:deps` + `build`. Materializes `.grok/app-env.json` (auth-off). Sandbox-doc tests skip when `AGENTS.md` / `.grok/skills` are absent.
- **CI vs merge:** `main` has no branch protection. Green Actions is evidence, not a merge gate.
- **Browser:** not in this kernel slice (no UI change).
