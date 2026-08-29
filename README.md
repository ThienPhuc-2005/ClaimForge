# ClaimForge

Offline red-team auth desk. Import two captures (HAR, Burp Save-items XML, raw HTTP, or JWT), then:

- Findings (BOLA/IDOR, JWT, cookies, CORS, mass-assign)
- Playbook — kill chain + curl / raw HTTP (copy into your interceptor; this app never fires them)
- JWT Forge — alg none, role admin, swap sub
- AuthZ diff, object-id graph, loot / wordlists, session timeline

Everything runs in the browser. Lab capture (alice vs bob) loads by default.

## Run

```bash
npm install
npm run dev
```

Open the printed local URL. `npm run typecheck` and `npm test` cover parse / BOLA / forge.

## Scope

Authorized lab / engagement traffic only. Replay packs are for a proxy you control — ClaimForge does not send captured requests at live hosts.
