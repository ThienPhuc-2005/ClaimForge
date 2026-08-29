import type { ActorId, CapturedRequest, CookieRecord, JwtToken } from "./types.ts";
import { jwtSubject } from "./jwt.ts";

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
}

const OWNER_KEYS = /^(ownerid|owner_id|userid|user_id|accountid|account_id|customerid|customer_id|owner)$/i;
const OBJECT_KEYS = /^(id|invoiceid|invoice_id|orderid|order_id|objectid|object_id)$/i;

export function ownerLinks(text?: string): OwnerLink[] {
  if (!text) return [];
  try {
    const out: OwnerLink[] = [];
    walkOwners(JSON.parse(text), out, 0);
    return out;
  } catch {
    return [];
  }
}

function firstKeyed(rec: Record<string, unknown>, re: RegExp): string | null {
  for (const [k, v] of Object.entries(rec)) {
    if (re.test(k) && v != null && (typeof v === "string" || typeof v === "number")) return String(v);
  }
  return null;
}

function walkOwners(value: unknown, into: OwnerLink[], depth: number) {
  if (depth > 8 || value == null) return;
  if (Array.isArray(value)) {
    for (const v of value) walkOwners(v, into, depth + 1);
    return;
  }
  if (typeof value === "object") {
    const rec = value as Record<string, unknown>;
    const owner = firstKeyed(rec, OWNER_KEYS);
    const id = firstKeyed(rec, OBJECT_KEYS);
    if (owner != null && id != null && owner !== id) {
      into.push({ owner, object: id });
    }
    for (const v of Object.values(rec)) walkOwners(v, into, depth + 1);
  }
}

function pushIdentity(into: Set<string>, v: unknown) {
  if (v == null) return;
  const s = String(v).trim();
  if (s && s.length < 128 && !/^https?:/i.test(s)) into.add(s);
}

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

function allIdentities(jwts: JwtToken[]): Set<string> {
  const s = new Set<string>();
  for (const actor of ["A", "B"] as const) {
    for (const id of actorIdentities(jwts, actor)) s.add(id);
  }
  return s;
}

/**
 * Object ids this actor owns. JWT `sub` is an identity, never an object id —
 * unverified tokens must not mark /resource/{sub} as owned, and a numeric sub
 * colliding with an invoice id is not ownership proof.
 * Proof is ownerId/userId in a body (owner ≠ object), or this actor's inventory
 * list when those ids are not themselves JWT subjects.
 */
export function ownedObjects(
  requests: CapturedRequest[],
  jwts: JwtToken[],
  actor: ActorId,
  cookies?: CookieRecord[],
): Set<string> {
  const owned = new Set<string>();
  const mine = actorIdentities(jwts, actor, cookies);
  const all = cookies
    ? new Set([...allIdentities(jwts), ...actorIdentities(jwts, "A", cookies), ...actorIdentities(jwts, "B", cookies)])
    : allIdentities(jwts);
  for (const req of requests) {
    for (const rel of [...ownerLinks(req.responseBody), ...ownerLinks(req.requestBody)]) {
      if (mine.has(rel.owner) && !all.has(rel.object)) owned.add(rel.object);
    }
  }
  for (const req of requests.filter((r) => r.actor === actor)) {
    try {
      const body = req.responseBody ? (JSON.parse(req.responseBody) as Record<string, unknown>) : null;
      const inv = body?.invoices ?? body?.orders;
      if (Array.isArray(inv)) {
        for (const v of inv) {
          const id = typeof v === "object" && v && "id" in v ? String((v as { id: unknown }).id) : String(v);
          if (!all.has(id) && isIdentifier(id, "id")) owned.add(id);
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
