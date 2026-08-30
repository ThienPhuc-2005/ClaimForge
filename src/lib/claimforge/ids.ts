import type { ActorId, CapturedRequest, CookieRecord, JwtToken } from "./types.ts";
import { jwtSubject } from "./jwt.ts";
import { DEFAULT_POLICY, isTrustedJwtIdentity, routeClass, type AnalysisPolicy } from "./policy.ts";

const ID_KEYS = /^(id|user_?id|account_?id|owner_?id|customer_?id|org_?id|uid|sub)$/i;
const ARRAY_ID = /(^ids?$|invoices|orders|users|accounts|objects)/i;
const SKIP_NUM = /^(0|1|200|201|204|301|302|304|400|401|403|404|500|502|503)$/;
const YEAR = /^(19|20)\d{2}$/;
const PATH_STOP =
  /^(api|v\d+|public|catalog|health|status|docs|openapi|swagger|assets|static|feed|marketing|blog|admin|users?|invoices?|orders?|items?|me|login|logout|auth|session|token|search|new|edit|create|update|delete|lab)$/i;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ULID_RE = /^[0-9A-HJKMNP-TV-Z]{26}$/;
const PREFIXED_RE = /^[a-z]{2,8}[_-][A-Za-z0-9]{4,32}$/;
const HEX_RE = /^[0-9a-f]{12,32}$/i;
const SLUG_RE = /^[a-z0-9]+(?:-[a-z0-9]+)+$/i;
const MONGO_RE = /^[0-9a-f]{24}$/i;

export function isUuid(value: string): boolean {
  return UUID_RE.test(value);
}

export function isUlid(value: string): boolean {
  return ULID_RE.test(value);
}

export function isPrefixedId(value: string): boolean {
  if (!PREFIXED_RE.test(value) || PATH_STOP.test(value.split(/[_-]/)[0] ?? "")) return false;
  const rest = value.slice(value.search(/[_-]/) + 1);
  return /[0-9]/.test(rest) || /[A-Z]/.test(rest);
}

export function isSlugId(value: string): boolean {
  if (!SLUG_RE.test(value) || PATH_STOP.test(value)) return false;
  if (value.length > 64) return false;
  return /\d/.test(value);
}

export function isIdentifier(value: string, key?: string): boolean {
  if (!value || SKIP_NUM.test(value)) return false;
  if (YEAR.test(value) && !(key && ID_KEYS.test(key))) return false;
  if (key && (ID_KEYS.test(key) || /id$/i.test(key))) {
    if (PATH_STOP.test(value) && !/\d/.test(value)) return false;
    return value.length >= 1 && value.length <= 128;
  }
  if (/^[0-9]{3,18}$/.test(value) && key && ARRAY_ID.test(key)) return true;
  if (isUuid(value) || isUlid(value) || isPrefixedId(value) || MONGO_RE.test(value)) return true;
  if (HEX_RE.test(value) && !YEAR.test(value)) return true;
  if (isSlugId(value)) return true;
  if (/^[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}$/.test(value)) return true;
  return false;
}

export function isPathIdentifier(seg: string): boolean {
  if (!seg || PATH_STOP.test(seg) || YEAR.test(seg)) return false;
  if (/^[0-9]{1,18}$/.test(seg)) return true;
  return isUuid(seg) || isUlid(seg) || isPrefixedId(seg) || isSlugId(seg) || HEX_RE.test(seg) || MONGO_RE.test(seg);
}

export function pathIds(path: string): string[] {
  return path.split("/").filter((seg) => isPathIdentifier(seg));
}

export function walkIdFields(
  value: unknown,
  into: Set<string>,
  depth = 0,
  parentKey?: string,
) {
  if (depth > 8 || value == null) return;
  if (typeof value === "string" || typeof value === "number") {
    const s = String(value);
    if (isIdentifier(s, parentKey) || (parentKey && ID_KEYS.test(parentKey))) into.add(s);
    return;
  }
  if (Array.isArray(value)) {
    for (const v of value) walkIdFields(v, into, depth + 1, parentKey);
    return;
  }
  if (typeof value === "object") {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      walkIdFields(v, into, depth + 1, k);
    }
  }
}

export function bodyIds(text?: string): Set<string> {
  const s = new Set<string>();
  if (!text) return s;
  try {
    walkIdFields(JSON.parse(text), s);
  } catch {
    /* ignore non-json */
  }
  return s;
}

export interface OwnerLink {
  owner: string;
  object: string;
  field: string;
}

const OWNER_KEYS = /^(ownerid|owner_id|userid|user_id|accountid|account_id|customerid|customer_id|owner)$/i;
const OBJECT_KEYS = /^(id|invoiceid|invoice_id|orderid|order_id|objectid|object_id)$/i;

export function ownerLinks(text?: string, allowedOwnerFields?: string[]): OwnerLink[] {
  if (!text) return [];
  try {
    const out: OwnerLink[] = [];
    const allow = allowedOwnerFields?.map((f) => f.toLowerCase());
    walkOwners(JSON.parse(text), out, 0, allow);
    return out;
  } catch {
    return [];
  }
}

function firstKeyed(
  rec: Record<string, unknown>,
  re: RegExp,
): { key: string; value: string } | null {
  for (const [k, v] of Object.entries(rec)) {
    if (re.test(k) && v != null && (typeof v === "string" || typeof v === "number")) {
      return { key: k, value: String(v) };
    }
  }
  return null;
}

function walkOwners(value: unknown, into: OwnerLink[], depth: number, allow?: string[]) {
  if (depth > 8 || value == null) return;
  if (Array.isArray(value)) {
    for (const v of value) walkOwners(v, into, depth + 1, allow);
    return;
  }
  if (typeof value === "object") {
    const rec = value as Record<string, unknown>;
    const owner = firstKeyed(rec, OWNER_KEYS);
    const id = firstKeyed(rec, OBJECT_KEYS);
    if (owner != null && id != null && owner.value !== id.value) {
      if (!allow || allow.includes(owner.key.toLowerCase())) {
        into.push({ owner: owner.value, object: id.value, field: owner.key });
      }
    }
    for (const v of Object.values(rec)) walkOwners(v, into, depth + 1, allow);
  }
}

function pushIdentity(into: Set<string>, v: unknown) {
  if (v == null) return;
  const s = String(v).trim();
  if (s && s.length < 128 && !/^https?:/i.test(s)) into.add(s);
}

/** Seen identities from JWT/cookies — not a trust decision. */
export function actorIdentities(jwts: JwtToken[], actor: ActorId, cookies?: CookieRecord[]): Set<string> {
  const ids = new Set<string>();
  for (const j of jwts.filter((x) => x.actor === actor)) {
    const sub = jwtSubject(j);
    if (sub) ids.add(sub);
    const p = j.payload;
    pushIdentity(ids, p.uid);
    pushIdentity(ids, p.userId);
    pushIdentity(ids, p.user_id);
    pushIdentity(ids, p.account_id);
    pushIdentity(ids, p.accountId);
    pushIdentity(ids, p.email);
    pushIdentity(ids, p.preferred_username);
  }
  if (cookies) {
    for (const c of cookies.filter((x) => x.actor === actor)) {
      if (/^(user|uid|sub|account)$/i.test(c.name) && c.value && c.value.length < 80) ids.add(c.value);
    }
  }
  return ids;
}

export interface OwnershipOpts {
  policy?: AnalysisPolicy;
  declaredLabel?: string;
  declaredLabels?: Partial<Record<ActorId, string>>;
}

/**
 * Identities allowed to prove ownership.
 * Unverified JWT `sub` / client cookies never qualify.
 * Analyst-declared actor labels always qualify.
 */
export function trustedIdentities(
  jwts: JwtToken[],
  actor: ActorId,
  opts?: OwnershipOpts,
): Set<string> {
  const policy = opts?.policy ?? DEFAULT_POLICY;
  const ids = new Set<string>();
  const label = (opts?.declaredLabel ?? opts?.declaredLabels?.[actor] ?? "").trim();
  if (label) ids.add(label);
  for (const j of jwts.filter((x) => x.actor === actor)) {
    if (!isTrustedJwtIdentity(j, policy)) continue;
    const sub = jwtSubject(j);
    if (sub) ids.add(sub);
    const p = j.payload;
    pushIdentity(ids, p.uid);
    pushIdentity(ids, p.userId);
    pushIdentity(ids, p.user_id);
    pushIdentity(ids, p.account_id);
    pushIdentity(ids, p.accountId);
    pushIdentity(ids, p.email);
    pushIdentity(ids, p.preferred_username);
  }
  return ids;
}

function allTrusted(jwts: JwtToken[], opts?: OwnershipOpts): Set<string> {
  const s = new Set<string>();
  for (const actor of ["A", "B"] as const) {
    for (const id of trustedIdentities(jwts, actor, opts)) s.add(id);
  }
  return s;
}

/**
 * Object ids this actor owns under the policy trust boundary.
 *
 * Never: request body, query, path, unverified JWT sub.
 * Trusted: analyst-declared label; verified JWT; response owner fields / inventory
 * on identity or private routes.
 */
export function ownedObjects(
  requests: CapturedRequest[],
  jwts: JwtToken[],
  actor: ActorId,
  cookies?: CookieRecord[],
  opts?: OwnershipOpts,
): Set<string> {
  void cookies;
  const policy = opts?.policy ?? DEFAULT_POLICY;
  const owned = new Set<string>();
  const mine = trustedIdentities(jwts, actor, { ...opts, policy });
  const all = allTrusted(jwts, { ...opts, policy });
  const jwtSubjects = new Set<string>();
  for (const side of ["A", "B"] as const) {
    for (const id of actorIdentities(jwts, side, cookies)) jwtSubjects.add(id);
  }
  const fields = policy.trustedOwnershipFields;

  for (const req of requests) {
    const klass = routeClass(req.path, policy);
    if (klass === "public" || klass === "shared") continue;
    for (const rel of ownerLinks(req.responseBody, fields)) {
      if (jwtSubjects.has(rel.object)) continue;
      if (mine.has(rel.owner) && !all.has(rel.object)) owned.add(rel.object);
    }
  }

  for (const req of requests.filter((r) => r.actor === actor)) {
    const klass = routeClass(req.path, policy);
    if (klass !== "identity" && klass !== "private" && klass !== "unknown") continue;
    try {
      const body = req.responseBody ? (JSON.parse(req.responseBody) as Record<string, unknown>) : null;
      if (!body) continue;
      for (const field of policy.inventoryFields) {
        const inv = body[field];
        if (!Array.isArray(inv)) continue;
        for (const v of inv) {
          const id = typeof v === "object" && v && "id" in v ? String((v as { id: unknown }).id) : String(v);
          if (jwtSubjects.has(id) || all.has(id)) continue;
          if (isIdentifier(id, "id")) owned.add(id);
        }
      }
    } catch {
      /* ignore */
    }
  }
  return owned;
}

export function actorIds(requests: CapturedRequest[], jwts: JwtToken[], actor: ActorId): string[] {
  const s = new Set<string>(ownedObjects(requests, jwts, actor));
  for (const req of requests.filter((r) => r.actor === actor)) {
    for (const id of bodyIds(req.responseBody)) s.add(id);
    for (const id of bodyIds(req.requestBody)) s.add(id);
    for (const id of pathIds(req.path)) s.add(id);
  }
  return [...s].slice(0, 80);
}
