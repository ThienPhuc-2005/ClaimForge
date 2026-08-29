# ClaimForge

Client-side red-team auth desk. Import two captures (HAR, Burp Save-items XML, raw HTTP, or JWT), then:

- Findings (BOLA/IDOR, JWT including RS256, cookies, CORS, mass-assign)
- Playbook — kill chain + curl / raw HTTP (copy into your interceptor; this app never fires them)
- JWT Forge — alg none, role admin, swap sub, HS256 sign, RS256 / JWKS verify, iss/aud
- AuthZ diff, object-id graph, loot / wordlists, session timeline

Analysis runs in the browser. A hosted shell may still load platform scripts, so this is **client-side processing**, not a fully air-gapped offline binary. Lab capture (alice vs bob) loads by default.

![ClaimForge desk](docs/screenshots/desk.png)

## Run

```bash
npm ci
npm run dev
```

`npm run typecheck`, `npm test`, `npm run lint`, and `npm run build` are the gates.

## Scope

Authorized lab / engagement traffic only. Replay packs are for a proxy you control — ClaimForge does not send captured requests at live hosts (optional JWKS URL fetch is the only network call you can opt into).

## Threat model and limitations

See [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).
