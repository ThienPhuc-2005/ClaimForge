# ClaimForge

Client-side red-team auth desk. Import two captures (HAR, Burp Save-items XML, raw HTTP, or JWT), then:

1. **Findings** — BOLA/IDOR, JWT, cookies, CORS, mass-assign. Observation / Suspicion / Confirmed.
2. **Playbook** — kill chain + curl / raw HTTP (copy into your interceptor; this app never fires them).
3. **Forge** — alg none, role admin, swap sub, HS256 sign, RS256 / JWKS verify, iss/aud.

Inspect (AuthZ diff, ID graph, loot, timeline, traffic, victim lab) is behind **More**.

Analysis runs in the browser. A hosted shell may still load platform scripts, so this is **client-side processing**, not a fully air-gapped offline binary. Lab capture (alice vs bob) loads by default.

![ClaimForge desk](docs/screenshots/desk.png)

## Run

```bash
npm ci
npm run dev
```

Gates: `npm run typecheck`, `npm run lint`, `npm run test:claimforge`, `npm run build`.

GitHub Actions (`.github/workflows/ci.yml`) runs `npm ci`, `npm run typecheck`, `npm run lint`, and `npm run test:claimforge`. Parser fuzz and accuracy fixtures live in `src/lib/claimforge/parse.fuzz.test.ts` and `accuracy.test.ts`.

Heuristics are capture-side. Confirmed BOLA needs `ownerId` / inventory, not an unverified JWT `sub`. Replay curls are for an authorized lab proxy.

## Scope

Authorized lab / engagement traffic only. Replay packs are for a proxy you control — ClaimForge does not send captured requests at live hosts (optional JWKS URL fetch is the only network call you can opt into). Exports redact tokens, cookies, and passwords.

## Threat model and limitations

See [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).
