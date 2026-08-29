import type { CapturedRequest } from "./types.ts";
import { pathIds } from "./ids.ts";

export type AuthzClass = "observation" | "suspicion" | "confirmed";

const PUBLIC_PATH =
  /\/(public|catalog|health|status|docs|openapi|swagger|assets|static|feed|marketing|blog)\b/i;

function bodyLooksShared(text?: string): boolean {
  if (!text) return false;
  try {
    const v = JSON.parse(text) as unknown;
    if (!v || typeof v !== "object" || Array.isArray(v)) return false;
    const rec = v as Record<string, unknown>;
    if (rec.visibility === "public" || rec.isPublic === true || rec.public === true) return true;
    if (rec.shared === true || rec.visibility === "shared") return true;
    if (Array.isArray(rec.members) && rec.members.length >= 2) return true;
    if (Array.isArray(rec.sharedWith) && rec.sharedWith.length >= 1) return true;
    return false;
  } catch {
    return false;
  }
}

export function looksPublicOrShared(path: string, ...bodies: (string | undefined)[]): boolean {
  if (PUBLIC_PATH.test(path)) return true;
  return bodies.some((b) => bodyLooksShared(b));
}

export function classifySameObject(
  objectId: string,
  path: string,
  bodies: (string | undefined)[],
  ownedA: Set<string>,
  ownedB: Set<string>,
): AuthzClass {
  if (looksPublicOrShared(path, ...bodies)) return "observation";
  const aOwns = ownedA.has(objectId);
  const bOwns = ownedB.has(objectId);
  if (aOwns && !bOwns) return "confirmed";
  if (bOwns && !aOwns) return "confirmed";
  if (aOwns && bOwns) return "observation";
  return "suspicion";
}

export function strongestClass(list: AuthzClass[]): AuthzClass | null {
  if (list.includes("confirmed")) return "confirmed";
  if (list.includes("suspicion")) return "suspicion";
  if (list.includes("observation")) return "observation";
  return null;
}

/** Pair A/B 2xx hits that share a path object id. */
export function sameObjectHits(a: CapturedRequest[], b: CapturedRequest[]): CapturedRequest[][] {
  const pairs: CapturedRequest[][] = [];
  for (const ar of a) {
    if (ar.status < 200 || ar.status >= 300) continue;
    const ids = pathIds(ar.path);
    if (!ids.length) continue;
    for (const br of b) {
      if (br.status < 200 || br.status >= 300) continue;
      if (br.path !== ar.path) continue;
      pairs.push([ar, br]);
    }
  }
  return pairs;
}
