# Making CI a merge gate on `main`

Backlog and ADR-029 record that `main` has no branch protection, so a green
Actions run is *evidence*, not a gate. This is the procedure that closes that
gap. It is an operator action in GitHub settings — it cannot be committed into
the repository, so this file plus `main-ruleset.json` is the reproducible part.

## Plan requirement (check this first)

`ThienPhuc-2005/ClaimForge` is a **private** repo on a **personal** account.
On GitHub Free, protected branches and rulesets are limited to public repos. If
Settings → Rules is unavailable or refuses to save, that is why. Either:

- upgrade the account to GitHub Pro, or
- make the repository public (it holds no secrets; `.grok/` is gitignored), or
- move it to an organization on a plan that allows private rulesets.

## Import

1. Settings → Rules → Rulesets → **New ruleset** → **Import a ruleset**.
2. Upload `docs/operator/main-ruleset.json`.
3. Review, then **Create**.

## What the ruleset enforces

| Rule | Effect |
|------|--------|
| `deletion` | `main` cannot be deleted. |
| `non_fast_forward` | No force-push to `main`; history stays append-only. |
| `pull_request` | Every change to `main` lands through a PR. |
| `required_status_checks` | The `gates` check must pass before merge. |

`gates` is the job id in `.github/workflows/ci.yml`. The job has no `name:`
override, so the check GitHub reports is literally `gates`. It covers
typecheck, lint, `npm test`, `audit:deps`, and `build`. If the job is ever
renamed, the required check must be renamed with it or the gate silently stops
matching and every PR waits forever.

## Two choices worth understanding before you enable it

**Approvals are set to 0.** GitHub does not let you approve your own pull
request. On a solo repo any non-zero count makes `main` unmergeable by its only
maintainer. Raise it when a second maintainer exists, not before.

**`bypass_actors` is empty, so the rule applies to you too.** The current habit
of committing `docs(agent): record ...` straight onto `main` stops working —
those commits will need a PR like anything else. If that friction is not worth
it, either add the repository admin role as a bypass actor after import, or set
`"enforcement": "evaluate"` first to see what would have been blocked without
blocking it. Note that a bypass actor reopens exactly the hole this ruleset is
meant to close.

**Strict checks are on.** `strict_required_status_checks_policy` requires a PR
branch to be current with `main` before merging, so the tree that passed CI is
the tree that merges. It costs an occasional update when `main` moves mid-PR.
