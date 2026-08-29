# ClaimForge

Client-side red-team auth desk. Import two captures (HAR, Burp Save-items XML, raw HTTP, or JWT), then:

1. **Findings** — BOLA/IDOR, JWT (including RS256 / JWKS), cookies, CORS, mass-assign. Confidence is Observation / Suspicion / Confirmed. Confirmed is a capture heuristic, not a ship-it report.
2. **Playbook** — kill chain + curl / raw HTTP (copy into your interceptor; this app never fires them). Replay uses one actor's bearer only.
3. **Forge** — alg none, role admin, swap sub, HS256 sign, RS256 / JWKS verify, iss/aud. Editing claims clears any previously signed token.

Inspect (AuthZ diff, object-id graph, loot, timeline, traffic, victim lab) is behind **More**.

Analysis runs in the browser. A hosted shell may still load platform scripts, so this is **client-side processing**, not a fully air-gapped offline binary. Lab capture (alice vs bob) loads by default.

![ClaimForge desk](docs/screenshots/desk.png)

## Run

```bash
npm ci
npm run dev
```

Gates: `npm run typecheck`, `npm test`, `npm run lint`, `npm run build`.

CI (typecheck, lint, test, build, Playwright desk flow) runs on push to `main`. Parser fuzz + accuracy fixtures live in `src/lib/claimforge/parse.fuzz.test.ts` and `accuracy.test.ts`. Full UI flow: `npm run test:e2e` against a running preview (`E2E_URL`).

## Scope

Authorized lab / engagement traffic only. Replay packs are for a proxy you control — ClaimForge does not send captured requests at live hosts (optional JWKS URL fetch is the only network call you can opt into).

Exports redact JWT signatures, bearer tokens, cookies, and password fields in diffs and findings.

## Threat model and limitations

See [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).
