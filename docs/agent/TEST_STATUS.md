# Test status

- **When:** P1.4 on `feat/p1.4-audit` (not merged).
- **Branch:** `feat/p1.4-audit` (from `main` `944f81b` / P1.3 `4cefe02`)
- **Commands (this branch):**
  - `npm test` — expect **493 tests / 489 pass / 4 skip / 0 fail** on a GitHub checkout (sandbox-doc tests skip without `AGENTS.md` / `.grok/skills`). P1.4 adds 11 tests vs `main` 482.
  - `npm run typecheck` → pass
  - `npm run lint` → pass
  - `npm run audit:deps` → 0 high
  - `npm run build` → pass
- **CI:** wait for Actions on the draft PR. Green is evidence, not a merge gate (ADR-029).
- **Browser UI:** no Team UI yet (P1.6). Audit and members routes are API-only.
