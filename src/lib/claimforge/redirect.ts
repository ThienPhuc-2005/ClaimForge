import type { CapturedRequest, FindingConfidence, Severity } from "./types.ts";
import { headerValue } from "./cookies.ts";
import { isLabOrigin } from "./session.ts";
import type { ReasonCode } from "./evidence.ts";

/**
 * Open redirect (CWE-601 / OWASP A01). A client-controlled redirect target that
 * the server sends the browser to — off-origin or a dangerous scheme — is the
 * classic phishing / OAuth token-theft vector.
 *
 * Always Suspicion from a passive capture: a legitimate, server-validated
 * redirect_uri (registered OAuth client) looks identical on the wire, so this is
 * a candidate to verify by supplying an attacker target in a lab, never a proven
 * bug. We only flag when the honored/target location is off-origin or uses a
 * dangerous scheme AND it reflects a client-supplied parameter — a same-origin
 * `?next=/dashboard` login redirect is ignored.
 */

const REDIRECT_PARAM =
  /^(redirect(_?uri|_?url)?|redir|next|url|return(_?url|_?to|_?path)?|continue|dest(ination)?|callback|goto|forward|target|link|out|go|u|r)$/i;
const DANGEROUS_SCHEME = /^\s*(javascript|data|vbscript):/i;

function hostOf(u: string): string | null {
  try {
    return new URL(u).hostname.toLowerCase();
  } catch {
    return null;
  }
}

/** Host of a redirect target, resolving protocol-relative (//host) forms; null for a relative path. */
function targetHost(v: string): string | null {
  const t = v.trim();
  if (/^\s*(\/\\|\\\/|\/\/)/.test(t)) {
    return hostOf(`https:${t.replace(/^[\\/]+/, "//")}`);
  }
  return hostOf(t);
}

/** A target string that navigates off the request's own origin, or is dangerous. */
export function isExternalTarget(value: string, reqHost: string): boolean {
  const v = value.trim();
  if (!v) return false;
  if (DANGEROUS_SCHEME.test(v)) return true;
  // protocol-relative (//evil, /\evil, \/\/evil) — browsers treat as absolute.
  if (/^\s*(\/\\|\\\/|\/\/)/.test(v)) return true;
  const h = hostOf(v); // absolute URL only; a relative path yields null (same-origin)
  if (!h) return false;
  return h !== reqHost;
}

export function isDangerousScheme(value: string): boolean {
  return DANGEROUS_SCHEME.test(value.trim());
}

interface Candidate {
  param: string;
  value: string;
}

function redirectCandidates(req: CapturedRequest): Candidate[] {
  const out: Candidate[] = [];
  const add = (param: string, value: string) => {
    if (REDIRECT_PARAM.test(param) && value.trim()) out.push({ param, value });
  };
  // Query string.
  try {
    const u = new URL(req.url, "https://req.local");
    for (const [k, v] of u.searchParams) add(k, v);
  } catch {
    /* ignore */
  }
  // Form / JSON body.
  const body = req.requestBody ?? "";
  if (body) {
    try {
      const j = JSON.parse(body) as unknown;
      if (j && typeof j === "object" && !Array.isArray(j)) {
        for (const [k, v] of Object.entries(j as Record<string, unknown>)) {
          if (typeof v === "string") add(k, v);
        }
      }
    } catch {
      for (const pair of body.split("&")) {
        const eq = pair.indexOf("=");
        if (eq < 0) continue;
        const k = pair.slice(0, eq);
        let v = pair.slice(eq + 1);
        try {
          v = decodeURIComponent(v.replace(/\+/g, " "));
        } catch {
          /* keep raw */
        }
        add(decodeURIComponent(k), v);
      }
    }
  }
  return out;
}

export interface RedirectHit {
  method: string;
  template: string;
  path: string;
  status: number;
  param: string;
  target: string;
  location?: string;
  origin: string;
  lab: boolean;
  dangerous: boolean;
  reflected: boolean;
  confidence: FindingConfidence;
  severity: Severity;
  reasonCodes: ReasonCode[];
}

export function openRedirects(requests: CapturedRequest[]): RedirectHit[] {
  const hits: RedirectHit[] = [];
  const seen = new Set<string>();
  for (const req of requests) {
    if (req.method === "PASTE") continue;
    const reqHost = hostOf(req.url) ?? "";
    if (!reqHost) continue;
    const candidates = redirectCandidates(req).filter(
      (c) => isExternalTarget(c.value, reqHost) || isDangerousScheme(c.value),
    );
    if (!candidates.length) continue;

    const location = headerValue(req.responseHeaders, "location");
    const is3xx = req.status >= 300 && req.status < 400;

    for (const c of candidates) {
      const key = `${req.method}:${req.template}:${c.param}`;
      if (seen.has(key)) continue;

      const dangerous = isDangerousScheme(c.value);
      // Reflected: the server issued a redirect whose Location carries this target.
      const reflected =
        is3xx &&
        Boolean(location) &&
        (location!.includes(c.value.trim()) ||
          (targetHost(location!) !== null && targetHost(location!) === targetHost(c.value)) ||
          (dangerous && DANGEROUS_SCHEME.test(location!)));

      let confidence: FindingConfidence;
      let severity: Severity;
      const reasonCodes: ReasonCode[] = [];
      if (reflected) {
        confidence = "suspicion";
        severity = dangerous ? "high" : "medium";
        reasonCodes.push(dangerous ? "OPEN_REDIRECT_DANGEROUS_SCHEME" : "OPEN_REDIRECT_REFLECTED", "IMPACT_NOT_PROVEN");
      } else {
        // A dangerous/off-origin target sits in a redirect param, but no honoring
        // redirect was observed in this capture.
        confidence = "observation";
        severity = dangerous ? "medium" : "low";
        reasonCodes.push("OPEN_REDIRECT_PARAM_UNVERIFIED");
        if (dangerous && !reasonCodes.includes("OPEN_REDIRECT_DANGEROUS_SCHEME")) {
          reasonCodes.unshift("OPEN_REDIRECT_DANGEROUS_SCHEME");
        }
      }
      seen.add(key);
      hits.push({
        method: req.method,
        template: req.template,
        path: req.path,
        status: req.status,
        param: c.param,
        target: c.value,
        location: location ?? undefined,
        origin: req.origin,
        lab: isLabOrigin(req.origin),
        dangerous,
        reflected,
        confidence,
        severity,
        reasonCodes,
      });
    }
  }
  return hits;
}
