# Operator procedure — first Team tenant (OIDC owner)

Creating a tenant and the first `owner` is an operator procedure. There is **no HTTP endpoint** for this. A public `POST /api/team/tenants` must not exist.

P1.2 does not JIT-provision `team_member` on OIDC callback. The owner row must exist before that subject can log in.

## Prerequisites

1. Postgres (not the preview PGLite fallback).
2. Product migrations applied (`0003` kernel tables at minimum; `0004` for OIDC login):

   ```bash
   DATABASE_URL=postgres://… npm run db:migrate
   ```

3. Environment (never command-line flags):

   | Variable | Rule |
   |----------|------|
   | `DATABASE_URL` | Required. The CLI refuses to start without it and never bootstraps into temporary PGLite. |
   | `CLAIMFORGE_TEAM_BOOTSTRAP_SECRET` | Required, length ≥ 16. Compared timing-safe by `unlockBootstrap`. Empty/missing disables bootstrap. |

Do not put the bootstrap secret, OIDC `client_secret`, session tokens, or the raw OIDC `sub` in argv, logs, tickets, or shell history if you can avoid it (`HISTCONTROL=ignorespace`, or a secrets file read into the environment).

## Command

```bash
DATABASE_URL=postgres://… \
CLAIMFORGE_TEAM_BOOTSTRAP_SECRET=… \
npm run team:bootstrap -- \
  --slug acme \
  --name "Acme" \
  --issuer https://idp.example \
  --sub "IdP-subject-exactly-as-issued"
```

Flags:

- `--slug` — tenant slug (`[a-z0-9]` + hyphens, 2–64).
- `--name` — display name.
- `--issuer` — OIDC issuer used to derive `user_key` (same string as `CLAIMFORGE_TEAM_OIDC_ISSUER` at login).
- `--sub` — exact OIDC subject. **Not trimmed.**

`user_key = oidc:` + `sha256(JSON.stringify([issuer, sub]))`.

There is no `--secret` flag. Passing `--secret`, `--token`, or similar is rejected.

## Output

One JSON line on stdout, and nothing else:

```json
{"tenantId":"…","slug":"acme","userKey":"oidc:…"}
```

`userKey` is the derived membership key. The CLI does not print the bootstrap secret, client secret, tokens, or raw `sub`.

Keep the printed `user_key` if you need to confirm the IdP subject mapping. Subsequent members are added through a verified `TenantContext` of **that** tenant (RBAC on who may add members is P1.3).

## Fail-closed

| Condition | Exit | stderr (safe) |
|-----------|------|----------------|
| Missing `--slug` / `--name` / `--issuer` / `--sub` | 1 | `… is required` / `slug is invalid` / `oidc subject is invalid` |
| Secret passed as an argument | 1 | `bootstrap secret must come from the environment` |
| Missing `DATABASE_URL` | 1 | `DATABASE_URL is required` |
| Missing/short bootstrap secret | 1 | `bootstrap is not configured` / `bootstrap denied` |
| `team_tenant` / `team_member` missing | 1 | `team schema is not migrated` |
| Duplicate slug | 1 | `tenant already exists` |
| Other database errors | 1 | `bootstrap failed` (no connection string, no secret, no `sub`) |

Tenant + owner insert is one transaction (`unlockBootstrap` + `bootstrapTenant` on a single TeamSql connection). Failure rolls back both.

## After bootstrap

OIDC login (`GET /api/team/oidc/login?slug=…`) still fail-closes without `CLAIMFORGE_TEAM_OIDC_*` and `CLAIMFORGE_TEAM_SEAL_KEY`. Unknown subjects are 404; they are not inserted.

Do not merge this CLI into a public admin UI in P1.2.
