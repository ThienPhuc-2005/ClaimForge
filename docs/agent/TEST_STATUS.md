# Test status

- **When:** remainder P0 + CI repair (this session)
- **HEAD:** `ba7d41b3482b4734cc22dbb9646066b692897d7c`
- **Repair SHA:** `e16575e71f0adbf00efc5b6404594d5b3b10decd`
- **Compared against:** `8740c6fa43c29e1bf59485e74ce332d2032f202c` (last green CI before remainder)
- **Session-start HEAD:** `4fdf31b83017730d61b0a5bbcfec21cbe71d9c7d` — CI run 18 **379 pass / 8 fail**
- **Working tree:** untracked `attachments/` only after this snapshot
- **Commands:**
  - `npm test` → **387 pass / 0 fail** (sandbox). GitHub-checkout sim: **383 pass / 4 skip / 0 fail**
  - `npm run typecheck` → pass
  - `npm run lint` → pass
  - `npm run audit:deps` → 0 vulnerabilities (`--audit-level=high`)
  - `npm run build` → pass
- **CI workflow:** typecheck + lint + `npm test` + `audit:deps` + `build`. Materializes `.grok/app-env.json` (auth-off). Sandbox-doc tests skip when `AGENTS.md` / `.grok/skills` are absent.
- **CI:** https://github.com/ThienPhuc-2005/ClaimForge/actions/runs/33292213402 (success)
- **Browser:** Load lab capture → More → Policy → invalid regex blocked. Role hierarchy Apply: mass-assign observation/high → confirmed/high. Export PDF. Dev smoke: no console/page errors.
