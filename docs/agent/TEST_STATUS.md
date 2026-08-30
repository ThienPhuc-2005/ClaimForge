# Test status

- **When:** 2026-08-30 (this session)
- **Base SHA:** `b7665b7979e0aa92eee5245fd941d534f19f2541`
- **Commands:**
  - `npm run test:claimforge` → **92 pass / 0 fail**
  - `npm run typecheck` → pass
  - `npm run lint` → pass
  - `npm run build` → not run this session (core-only slice)
- **New tests:** `src/lib/claimforge/p0-trust-boundary.test.ts`
  - request body `ownerId` must not confirm BOLA
  - query `ownerId` must not confirm BOLA
  - unverified JWT `sub` is not trusted identity
  - unverified JWT `sub` colliding with object id must not confirm
  - response `ownerId` + analyst map still confirms
  - engine/rule/policy/input/result hashes are stable
