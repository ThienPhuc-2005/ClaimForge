import type { ActorId, CapturedRequest, FindingConfidence, JwtToken } from "./types.ts";
import { DEFAULT_POLICY, isPrivilegedRole, isSuccessStatus, type AnalysisPolicy } from "./policy.ts";
import { isLabOrigin } from "./session.ts";
import type { ReasonCode } from "./evidence.ts";

/**
 * Broken Function-Level Authorization (BFLA / OWASP API5): a low-privilege
 * actor reaching an administrative *function*, distinct from BOLA which is a
 * cross-actor read of one *object*. We never invent the required role from the
 * route name alone — Confirmed needs a verified low-privilege role AND observed
 * enforcement (a 403 on the same function template), so the bypass is a fact.
 *
 * Enforcement means 403 (authenticated but forbidden), NOT 401: a 401 only says
 * the caller was unauthenticated, which is true of any endpoint before login and
 * proves nothing about role-level access control.
 */

// Admin path segments (anchored to a full segment so "/manage-subscription" and
// self-service routes are not swept in). Self routes (/me, /users/me) are excluded.
const ADMIN_SEG =
  /\/(admin|administrator|management|manage|console|internal|superuser|sysadmin|actuator|impersonate|masquerade)(\/|$)/i;
const PRIV_MUTATION = /\/(roles|permissions|grants|entitlements|feature-?flags)(\/|$)/i;
const PRIV_USER_ACTION =
  /\/users?\/[^/]+\/(role|roles|permissions|status|enable|disable|activate|deactivate|promote|demote|ban|unban)(\/|$)/i;
const BILLING_REFUND = /\/billing\/refund(\/|$)/i;
const SELF = /\/(me|users\/me)(\/|$)/i;

export function isPrivilegedFunction(path: string): boolean {
  const p = path.split("?")[0] ?? path;
  if (SELF.test(p)) return false;
  return ADMIN_SEG.test(p) || PRIV_MUTATION.test(p) || PRIV_USER_ACTION.test(p) || BILLING_REFUND.test(p);
}

function rolesOf(j: JwtToken): string[] {
  const r = j.payload.role ?? j.payload.roles;
  if (Array.isArray(r)) return r.map((x) => String(x)).filter(Boolean);
  return r == null || r === "" ? [] : [String(r)];
}

function isAdminFlag(j: JwtToken): boolean {
  const ia = j.payload.is_admin;
  return ia === true || ia === 1 || (typeof ia === "string" && /^(true|1|yes)$/i.test(ia.trim()));
}

function tokenPrivileged(policy: AnalysisPolicy, j: JwtToken): boolean {
  return isAdminFlag(j) || rolesOf(j).some((r) => isPrivilegedRole(policy, r));
}

export interface ActorRole {
  label: string;
  hasSignal: boolean;
  privileged: boolean;
  verifiedNonPriv: boolean;
}

/** Summarize an actor's role signal across all their tokens (verified wins). */
export function actorRole(jwts: JwtToken[], actor: ActorId, policy: AnalysisPolicy = DEFAULT_POLICY): ActorRole {
  const mine = jwts.filter((j) => j.actor === actor);
  const withSignal = mine.filter((j) => rolesOf(j).length || j.payload.is_admin !== undefined);
  const privileged = mine.some((j) => tokenPrivileged(policy, j));
  const verifiedNonPriv =
    !privileged &&
    withSignal.some((j) => j.sigStatus === "verified" && !tokenPrivileged(policy, j) && rolesOf(j).length > 0);
  const labelToken = withSignal.find((j) => j.sigStatus === "verified") ?? withSignal[0];
  const label = labelToken
    ? isAdminFlag(labelToken)
      ? "is_admin"
      : rolesOf(labelToken).join(",") || "unknown"
    : "unknown";
  return { label, hasSignal: withSignal.length > 0, privileged, verifiedNonPriv };
}

export interface BflaHit {
  actor: ActorId;
  method: string;
  template: string;
  path: string;
  status: number;
  actorRole: string;
  roleVerified: boolean;
  enforcementObserved: boolean;
  origin: string;
  lab: boolean;
  confidence: FindingConfidence;
  reasonCodes: ReasonCode[];
}

/**
 * Report an actor's 2xx on a privileged function when either the actor's role
 * is known to be non-privileged, or the same function template was forbidden
 * (403) elsewhere — enforcement exists and this call slipped through. Privileged
 * actors on their own admin routes are expected and never flagged.
 */
export function brokenFunctionLevelAuthz(
  requests: CapturedRequest[],
  jwts: JwtToken[],
  policy: AnalysisPolicy = DEFAULT_POLICY,
): BflaHit[] {
  const roles: Record<ActorId, ActorRole> = {
    A: actorRole(jwts, "A", policy),
    B: actorRole(jwts, "B", policy),
  };

  // Templates where any request was forbidden (403) → the function is enforced.
  // Template-scoped (not method-scoped) so verb-tampering bypasses are caught.
  const enforced = new Set<string>();
  for (const r of requests) {
    if (r.method === "PASTE") continue;
    if (r.status === 403) enforced.add(r.template);
  }

  const hits: BflaHit[] = [];
  const seen = new Set<string>();
  for (const req of requests) {
    if (req.method === "PASTE" || req.method === "OPTIONS") continue;
    if (!isPrivilegedFunction(req.path)) continue;
    if (!isSuccessStatus(req.status, policy)) continue;

    const role = roles[req.actor];
    if (role.privileged) continue; // privileged actor: expected

    const roleKnownNonPriv = role.hasSignal; // has a role signal and not privileged
    const enforcementObserved = enforced.has(req.template);
    if (!roleKnownNonPriv && !enforcementObserved) continue; // nothing ties it to a bypass

    const key = `${req.actor}:${req.method}:${req.template}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const confidence: FindingConfidence =
      roleKnownNonPriv && role.verifiedNonPriv && enforcementObserved ? "confirmed" : "suspicion";

    const reasonCodes: ReasonCode[] = ["BFLA_PRIVILEGED_FUNCTION", "BFLA_LOW_PRIV_ACTOR_2XX"];
    if (role.verifiedNonPriv) reasonCodes.push("BFLA_ROLE_VERIFIED");
    else reasonCodes.push("MISSING_VERIFIED_ROLE");
    if (enforcementObserved) reasonCodes.push("BFLA_ENFORCEMENT_OBSERVED");
    else reasonCodes.push("MISSING_FUNCTION_PRIVILEGE_PROOF");

    hits.push({
      actor: req.actor,
      method: req.method,
      template: req.template,
      path: req.path,
      status: req.status,
      actorRole: role.label,
      roleVerified: role.verifiedNonPriv,
      enforcementObserved,
      origin: req.origin,
      lab: isLabOrigin(req.origin),
      confidence,
      reasonCodes,
    });
  }
  return hits;
}
