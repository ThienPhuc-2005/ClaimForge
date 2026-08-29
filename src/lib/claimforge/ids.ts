import type { ActorId, CapturedRequest, JwtToken } from "./types.ts";
import { jwtSubject } from "./jwt.ts";

const ID_KEYS = /^(id|user_?id|account_?id|owner_?id|customer_?id|org_?id|uid|sub)$/i;
const ARRAY_ID = /(^ids?$|invoices|orders|users|accounts|objects)/i;
const SKIP_NUM = /^(0|1|200|201|204|301|302|304|400|401|403|404|500|502|503)$/;

export function isIdentifier(value: string, key?: string): boolean {
  if (!value || SKIP_NUM.test(value)) return false;
  if (/^20[0-9]{2}$/.test(value)) return false;
  if (key && (ID_KEYS.test(key) || /id$/i.test(key))) return true;
  if (/^[0-9]{3,}$/.test(value) && key && ARRAY_ID.test(key)) return true;
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) return true;
  if (/^[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}$/.test(value)) return true;
  return false;
}

export function pathIds(path: string): string[] {
  return path.split("/").filter((seg) => /^[0-9]+$/.test(seg) || /^[0-9a-f-]{8,}$/i.test(seg));
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

function walkOwners(value: unknown, into: OwnerLink[], depth: number) {
  if (depth > 8 || value == null) return;
  if (Array.isArray(value)) {
    for (const v of value) walkOwners(v, into, depth + 1);
    return;
  }
  if (typeof value === "object") {
    const rec = value as Record<string, unknown>;
    const owner = rec.ownerId ?? rec.owner_id ?? rec.userId ?? rec.user_id ?? rec.accountId;
    const id = rec.id ?? rec.invoiceId ?? rec.orderId;
    if (owner != null && id != null && String(owner) !== String(id)) {
      into.push({ owner: String(owner), object: String(id) });
    }
    for (const v of Object.values(rec)) walkOwners(v, into, depth + 1);
  }
}

function actorSubs(jwts: JwtToken[], actor: ActorId): Set<string> {
  const subs = new Set<string>();
  for (const j of jwts.filter((x) => x.actor === actor)) {
    const sub = jwtSubject(j);
    if (sub) subs.add(sub);
  }
  return subs;
}

function allSubs(jwts: JwtToken[]): Set<string> {
  const s = new Set<string>();
  for (const j of jwts) {
    const sub = jwtSubject(j);
    if (sub) s.add(sub);
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
): Set<string> {
  const owned = new Set<string>();
  const subs = actorSubs(jwts, actor);
  const subsAll = allSubs(jwts);
  for (const req of requests) {
    for (const rel of [...ownerLinks(req.responseBody), ...ownerLinks(req.requestBody)]) {
      if (subs.has(rel.owner) && !subsAll.has(rel.object)) owned.add(rel.object);
    }
  }
  for (const req of requests.filter((r) => r.actor === actor)) {
    try {
      const body = req.responseBody ? (JSON.parse(req.responseBody) as Record<string, unknown>) : null;
      const inv = body?.invoices;
      if (Array.isArray(inv)) {
        for (const v of inv) {
          const id = String(v);
          if (!subsAll.has(id)) owned.add(id);
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
  }
  return [...s].slice(0, 80);
}
