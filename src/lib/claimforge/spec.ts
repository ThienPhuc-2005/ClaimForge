import type { CapturedRequest, SpecCoverage, SpecOperation } from "./types.ts";

/**
 * OpenAPI 3 / Swagger 2 coverage. This never sends a request — it diffs the
 * *declared* API surface against the surface the capture actually touched, so
 * an analyst can see which endpoints (especially secured / write ones) were
 * never exercised, and which live routes are undocumented ("shadow") API.
 *
 * Matching is done by turning each declared path into a regex ({param} -> one
 * segment), so non-numeric path params (usernames, slugs) match correctly.
 * Requests are filtered to the spec's declared host(s) so third-party telemetry
 * in a browser HAR is not mistaken for shadow API. An endpoint counts as
 * "covered" only when a non-error (<400) response was seen — a 404/401/403/5xx
 * probe never meaningfully exercised it.
 *
 * JSON only: adding a YAML parser would widen the dependency surface of a
 * security tool for no analysis gain.
 */

const HTTP_METHODS = new Set(["get", "put", "post", "delete", "patch", "head", "options", "trace"]);
const STATIC_EXT = /\.(js|mjs|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|webp|avif)$/i;
const WRITE = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export function normalizeTemplate(t: string): string {
  const noQuery = t.split("?")[0] ?? t;
  const cleaned = noQuery
    .split("/")
    .map((seg) => (seg.startsWith("{") && seg.endsWith("}") && seg.length > 2 ? "{}" : seg))
    .join("/");
  const trimmed = cleaned.length > 1 ? cleaned.replace(/\/$/, "") : cleaned;
  return trimmed.startsWith("/") || trimmed === "" ? trimmed || "/" : `/${trimmed}`;
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Turn a declared path template into an anchored matcher; {param} -> one path segment. */
export function specPathMatcher(specPath: string): RegExp {
  const noQuery = specPath.split("?")[0] ?? specPath;
  const pat = noQuery
    .split("/")
    .map((seg) => (seg.startsWith("{") && seg.endsWith("}") && seg.length > 2 ? "[^/]+" : escapeRegex(seg)))
    .join("/");
  const withSlash = pat.startsWith("/") ? pat : `/${pat}`;
  return new RegExp(`^${withSlash.replace(/\/$/, "")}/?$`);
}

interface RawOp {
  security?: unknown;
  summary?: unknown;
  deprecated?: unknown;
}

function isObj(v: unknown): v is Record<string, unknown> {
  return Boolean(v) && typeof v === "object" && !Array.isArray(v);
}

function hasSecurity(sec: unknown): boolean {
  return Array.isArray(sec) && sec.length > 0;
}

function specPrefix(doc: Record<string, unknown>): string {
  if (typeof doc.basePath === "string") return doc.basePath.replace(/\/$/, ""); // Swagger 2
  if (Array.isArray(doc.servers) && isObj(doc.servers[0])) {
    const url = (doc.servers[0] as Record<string, unknown>).url;
    if (typeof url === "string") {
      try {
        const path = new URL(url, "https://spec.local").pathname.replace(/\/$/, "");
        return path === "/" ? "" : path;
      } catch {
        /* relative or template server url */
      }
    }
  }
  return "";
}

/** Declared host(s), lowercased, no port. Empty means "no host filter available". */
function specHosts(doc: Record<string, unknown>): Set<string> {
  const hosts = new Set<string>();
  if (typeof doc.host === "string" && doc.host.trim()) {
    hosts.add(doc.host.trim().toLowerCase().split(":")[0]!); // Swagger 2
  }
  if (Array.isArray(doc.servers)) {
    for (const s of doc.servers) {
      if (!isObj(s) || typeof s.url !== "string") continue;
      try {
        hosts.add(new URL(s.url, "https://spec.local").hostname.toLowerCase());
      } catch {
        /* templated/relative server url — no host */
      }
    }
  }
  hosts.delete("spec.local");
  return hosts;
}

function reqHost(req: CapturedRequest): string {
  try {
    return new URL(req.url).hostname.toLowerCase();
  } catch {
    try {
      return new URL(req.origin).hostname.toLowerCase();
    } catch {
      return "";
    }
  }
}

function reqPath(req: CapturedRequest): string {
  return (req.path.split("?")[0] ?? req.path) || "/";
}

export function buildSpecCoverage(specRaw: string, requests: CapturedRequest[]): SpecCoverage | undefined {
  const raw = specRaw.trim();
  if (!raw) return undefined;

  const base: SpecCoverage = {
    source: "openapi3",
    title: "",
    version: "",
    declaredCount: 0,
    coveredCount: 0,
    untested: [],
    shadow: [],
  };

  if (!raw.startsWith("{")) {
    return { ...base, error: "Only JSON specs are supported — export/convert your OpenAPI or Swagger doc to JSON." };
  }

  let doc: Record<string, unknown>;
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!isObj(parsed)) return { ...base, error: "Spec is not a JSON object." };
    doc = parsed;
  } catch (e) {
    return { ...base, error: e instanceof Error ? `Invalid JSON: ${e.message}` : "Invalid JSON." };
  }

  const source: SpecCoverage["source"] =
    typeof doc.swagger === "string" && doc.swagger.startsWith("2") ? "swagger2" : "openapi3";
  const info = isObj(doc.info) ? doc.info : {};
  const title = typeof info.title === "string" ? info.title : "";
  const version = typeof info.version === "string" ? info.version : "";
  const paths = isObj(doc.paths) ? doc.paths : {};
  const globalSecured = hasSecurity(doc.security);
  const prefix = specPrefix(doc);
  const hosts = specHosts(doc);

  // Requests in scope: those to a declared host (when we know the host).
  const inScope = requests.filter((r) => r.method !== "PASTE" && (hosts.size === 0 || hosts.has(reqHost(r))));

  interface DeclaredOp extends SpecOperation {
    matcher: RegExp;
  }
  const declared: DeclaredOp[] = [];
  for (const [rawPath, item] of Object.entries(paths)) {
    if (!isObj(item)) continue;
    const fullPath = `${prefix}${rawPath.startsWith("/") ? rawPath : `/${rawPath}`}`;
    const normalized = normalizeTemplate(fullPath);
    const matcher = specPathMatcher(fullPath);
    for (const [m, opUnknown] of Object.entries(item)) {
      const method = m.toLowerCase();
      if (!HTTP_METHODS.has(method)) continue;
      const op = (isObj(opUnknown) ? opUnknown : {}) as RawOp;
      const upper = method.toUpperCase();
      const statuses = new Set<number>();
      for (const r of inScope) {
        if (r.method.toUpperCase() !== upper) continue;
        if (matcher.test(reqPath(r))) statuses.add(r.status);
      }
      const covered = [...statuses].some((s) => s < 400); // a non-error response actually exercised it
      declared.push({
        matcher,
        method: upper,
        path: fullPath,
        normalized,
        secured: op.security === undefined ? globalSecured : hasSecurity(op.security),
        write: WRITE.has(upper),
        deprecated: op.deprecated === true,
        summary: typeof op.summary === "string" ? op.summary : "",
        covered,
        observedStatuses: [...statuses].sort((a, b) => a - b),
      });
    }
  }

  const untested = declared
    .filter((o) => !o.covered)
    .map(({ matcher: _m, ...o }) => o)
    .sort((a, b) => Number(b.secured || b.write) - Number(a.secured || a.write) || a.path.localeCompare(b.path));

  const shadow: SpecCoverage["shadow"] = [];
  const shadowSeen = new Set<string>();
  const shadowStatuses = new Map<string, Set<number>>();
  for (const r of inScope) {
    if (STATIC_EXT.test(reqPath(r))) continue;
    const method = r.method.toUpperCase();
    const declaredHere = declared.some((o) => o.method === method && o.matcher.test(reqPath(r)));
    if (declaredHere) continue;
    const norm = normalizeTemplate(r.template);
    const key = `${method} ${norm}`;
    const set = shadowStatuses.get(key) ?? new Set<number>();
    set.add(r.status);
    shadowStatuses.set(key, set);
    if (shadowSeen.has(key)) continue;
    shadowSeen.add(key);
    shadow.push({ method, template: norm, statuses: [] });
  }
  for (const s of shadow) s.statuses = [...(shadowStatuses.get(`${s.method} ${s.template}`) ?? [])].sort((a, b) => a - b);
  shadow.sort((a, b) => a.template.localeCompare(b.template));

  return {
    source,
    title,
    version,
    declaredCount: declared.length,
    coveredCount: declared.filter((o) => o.covered).length,
    untested,
    shadow,
  };
}
