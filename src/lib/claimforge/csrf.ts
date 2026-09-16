import type { ActorId, CapturedRequest, CookieRecord, FindingConfidence } from "./types.ts";
import { headerValue, parseCookieHeader } from "./cookies.ts";
import { DEFAULT_POLICY, routeClass, type AnalysisPolicy } from "./policy.ts";
import { bearerOf } from "./loot.ts";
import { isLabOrigin } from "./session.ts";
import type { ReasonCode } from "./evidence.ts";

/**
 * CSRF on state-changing requests (OWASP A01 / CWE-352). A passive capture can
 * never *confirm* CSRF — that needs a cross-site forged request in a browser —
 * so every hit is at most Suspicion (SameSite=None) or Observation (SameSite
 * unobserved / no attribute, where the modern Lax default already blocks
 * cross-site POST). Bearer-authed requests are excluded: a bearer is attached
 * by JS, not sent ambiently, so it is not forgeable the same way.
 */

const MUTATING = /^(POST|PUT|PATCH|DELETE)$/i;
const SESSION_COOKIE = /^(sid|session|sessionid|jsessionid|phpsessid|auth|token|jwt|refresh|access|connect\.sid)$/i;
const SKIP_COOKIE = /^(theme|locale|lang|tz|timezone|cookieconsent|optanon|csrf|xsrf)/i;
// Analytics / marketing cookies carry long opaque values but are not credentials.
const TRACKING_COOKIE = /^(_ga|_gid|_gat|_gcl|_fbp|_fbc|__utm|_hj|_pk_|ajs_|amplitude|mp_|_clck|_clsk|_uet|_scid|__stripe)/i;

// Anti-CSRF token carried in a request HEADER. X-Requested-With is intentionally
// excluded: frameworks add it to every XHR, so its presence does not prove the
// server validates it.
const CSRF_HEADER =
  /^(x-csrf-token|x-xsrf-token|x-csrftoken|x-xsrftoken|x-csrf|x-xsrf|csrf-token|xsrf-token|anti-csrf-token|__requestverificationtoken)$/i;
// Anti-CSRF token carried as a body/query FIELD NAME (never a value).
const CSRF_FIELD_NAME =
  /^(_?csrf(_?token)?|csrfmiddlewaretoken|authenticity_token|_?xsrf(_?token)?|__requestverificationtoken)$/i;

function isAuthCookieName(name: string, value: string): boolean {
  if (SKIP_COOKIE.test(name) || TRACKING_COOKIE.test(name)) return false;
  if (SESSION_COOKIE.test(name)) return true;
  if (/^__(host|secure)-/i.test(name)) return value.length >= 16; // secure-prefixed session cookies
  if (name.startsWith("_")) return false; // leading-underscore is the analytics convention
  return value.length >= 16;
}

export function hasAntiCsrfToken(req: CapturedRequest): boolean {
  for (const h of req.requestHeaders) {
    if (CSRF_HEADER.test(h.name.trim()) && h.value.trim()) return true;
  }
  // Query parameter names.
  try {
    const u = new URL(req.url, "https://spec.local");
    for (const k of u.searchParams.keys()) if (CSRF_FIELD_NAME.test(k)) return true;
  } catch {
    /* relative url without base handled above */
  }
  const body = req.requestBody ?? "";
  if (body) {
    try {
      const parsed = JSON.parse(body) as unknown;
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        for (const k of Object.keys(parsed as object)) if (CSRF_FIELD_NAME.test(k)) return true;
      }
    } catch {
      /* not JSON — fall through to form parsing */
    }
    for (const m of body.matchAll(/(?:^|&)([^=&]+)=/g)) {
      let name = m[1]!;
      try {
        name = decodeURIComponent(name);
      } catch {
        /* keep raw */
      }
      if (CSRF_FIELD_NAME.test(name.trim())) return true;
    }
  }
  return false;
}

type SameSiteClass = "none" | "protected" | "unknown";

/**
 * Least-protective SameSite across ALL Set-Cookie records for the request's auth
 * cookies. An explicit "none" anywhere wins. A record with no SameSite attribute
 * (null) is the browser Lax default → treated as unknown (observation), never as
 * None. Only Lax/Strict count as protected.
 */
function sameSiteFor(req: CapturedRequest, cookies: CookieRecord[], authNames: string[]): SameSiteClass {
  let sawRecord = false;
  let none = false;
  let protectedSeen = false;
  for (const rec of cookies) {
    if (rec.source !== "set-cookie" || rec.actor !== req.actor) continue;
    if (!authNames.includes(rec.name)) continue;
    sawRecord = true;
    const ss = (rec.flags.sameSite ?? "").toLowerCase();
    if (ss === "none") none = true;
    else if (ss === "lax" || ss === "strict") protectedSeen = true;
  }
  if (none) return "none";
  if (sawRecord && protectedSeen) return "protected";
  return "unknown";
}

export interface CsrfHit {
  actor: ActorId;
  method: string;
  template: string;
  path: string;
  status: number;
  origin: string;
  lab: boolean;
  cookieNames: string[];
  sameSite: "none" | "unknown";
  confidence: FindingConfidence;
  reasonCodes: ReasonCode[];
}

export function csrfExposures(
  requests: CapturedRequest[],
  cookies: CookieRecord[],
  policy: AnalysisPolicy = DEFAULT_POLICY,
): CsrfHit[] {
  const hits: CsrfHit[] = [];
  const seen = new Set<string>();
  for (const req of requests) {
    if (!MUTATING.test(req.method)) continue;
    if (routeClass(req.path, policy) === "public") continue;
    if (bearerOf(req)) continue; // bearer auth is not ambient

    const cookieHeader = headerValue(req.requestHeaders, "cookie");
    if (!cookieHeader) continue;
    const authNames = parseCookieHeader(cookieHeader, req.actor)
      .filter((c) => isAuthCookieName(c.name, c.value))
      .map((c) => c.name);
    if (!authNames.length) continue;
    if (hasAntiCsrfToken(req)) continue;

    const ss = sameSiteFor(req, cookies, authNames);
    if (ss === "protected") continue; // Lax/Strict blocks cross-site POST

    const key = `${req.actor}:${req.method}:${req.template}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const reasonCodes: ReasonCode[] = ["CSRF_STATE_CHANGE_COOKIE_AUTH", "CSRF_NO_TOKEN"];
    let confidence: FindingConfidence;
    if (ss === "none") {
      reasonCodes.push("CSRF_SAMESITE_NONE", "IMPACT_NOT_PROVEN");
      confidence = "suspicion";
    } else {
      reasonCodes.push("CSRF_SAMESITE_DEFAULT_LAX");
      confidence = "observation";
    }

    hits.push({
      actor: req.actor,
      method: req.method.toUpperCase(),
      template: req.template,
      path: req.path,
      status: req.status,
      origin: req.origin,
      lab: isLabOrigin(req.origin),
      cookieNames: [...new Set(authNames)],
      sameSite: ss,
      confidence,
      reasonCodes,
    });
  }
  return hits;
}
