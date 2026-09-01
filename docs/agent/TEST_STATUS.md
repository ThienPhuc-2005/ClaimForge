# Test status

- **When:** P1.6 on `feat/p1.6-team-ui` (not merged). Stacked on P1.5 `9e3c4ee`.
- **Branch:** `feat/p1.6-team-ui` (from `feat/p1.5-collab-http` / P1.4 `83059bb` / `main` `944f81b`)
- **Commands (this branch):**
  - `npm test` — expect **509 tests / 505 pass / 4 skip / 0 fail** on a GitHub checkout (sandbox-doc tests skip). P1.6 adds 6 tests vs P1.5 503.
  - `npm run typecheck` → pass
  - `npm run lint` → pass
  - `npm run audit:deps` → 0 high
  - `npm run build` → pass
- **CI:** wait for Actions on the draft PR. Green is evidence, not a merge gate (ADR-029).
- **Browser UI:** More → Team is API-backed inspect. Primary tabs unchanged.
