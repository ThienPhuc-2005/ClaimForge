# Test status

- **When:** P1.1 persist/context hardening (this session)
- **Branch:** `feat/p1-isolation-kernel` (do not treat this file as recording its own SHA)
- **Compared against:** `f1ed912` (`main`)
- **Commands (local, GitHub-checkout shape with materialized `.grok/app-env.json`):**
  - `npm test` → **412 tests / 408 pass / 4 skip / 0 fail**
  - `npm run typecheck` → pass
  - `npm run lint` → pass
  - `npm run audit:deps` → 0 vulnerabilities (`--audit-level=high`)
  - `npm run build` → pass
- **CI workflow:** typecheck + lint + `npm test` + `audit:deps` + `build`. Materializes `.grok/app-env.json` (auth-off). Sandbox-doc tests skip when `AGENTS.md` / `.grok/skills` are absent.
- **CI vs merge:** `main` has no branch protection. Green Actions is evidence, not a merge gate.
- **Browser:** not in this kernel slice (no UI change).
