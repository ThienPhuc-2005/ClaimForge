# Test status

- **When:** remainder P0 + CI session (after gates)
- **Remainder SHA:** `28760971f67eb6a5c9bf20a8891a5b3e43af84fe`
- **Working tree:** untracked `attachments/` only after handoff snapshot
- **Commands:**
  - `npm test` → **387 pass / 0 fail** (all `src/**/*.test.ts` + `scripts/*.test.mjs`)
  - `npm run typecheck` → pass
  - `npm run lint` → pass
  - `npm run audit:deps` → 0 vulnerabilities (`--audit-level=high`)
  - `npm run build` → pass
- **CI workflow:** typecheck + lint + `npm test` + `audit:deps` + `build`
- **Browser:** Load lab capture → More → Policy → invalid regex blocked. Role hierarchy Apply: mass-assign observation/high → confirmed/high. Export PDF. Dev smoke: no console/page errors, no overflow.
