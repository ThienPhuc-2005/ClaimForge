import type {
  CapturedRequest,
  CookieRecord,
  DiffRow,
  Finding,
  JwtToken,
  TimelineEvent,
  Workspace,
} from "./types.ts";
import { headerValue, parseCookieHeader, parseSetCookie } from "./cookies.ts";
import { extractJwtStrings, inspectJwt, jwtSubject } from "./jwt.ts";
import { parseHarLike, parseJwtPasted, resetParseIds } from "./parse.ts";
import { actorIds, ownedObjects, pathIds } from "./ids.ts";
import { buildIdGraph } from "./graph.ts";
import { buildSurface, buildWordlists, harvestLoot } from "./loot.ts";
import { buildPaths, buildReplays } from "./playbook.ts";

function collectArtifacts(requests: CapturedRequest[]) {
  const jwts: JwtToken[] = [];
  const cookies: CookieRecord[] = [];
  const seenJwt = new Set<string>();
  for (const req of requests) {
    const blob = [
      headerValue(req.requestHeaders, "authorization") ?? "",
      headerValue(req.requestHeaders, "cookie") ?? "",
      req.requestBody ?? "",
      req.responseBody ?? "",
      headerValue(req.responseHeaders, "authorization") ?? "",
    ].join("\n");
    for (const t of extractJwtStrings(blob)) {
      const key = req.actor + t;
      if (seenJwt.has(key)) continue;
      seenJwt.add(key);
      const ins = inspectJwt(t, req.actor, `${req.method} ${req.path}`);
      if (ins) jwts.push(ins);
    }
    const ck = headerValue(req.requestHeaders, "cookie");
    if (ck) cookies.push(...parseCookieHeader(ck, req.actor));
    const sc = headerValue(req.responseHeaders, "set-cookie");
    if (sc) cookies.push(...parseSetCookie(sc, req.actor));
  }
  return { jwts, cookies };
}

function buildTimeline(requests: CapturedRequest[]): TimelineEvent[] {
  const sorted = [...requests].sort((a, b) => a.startedAt - b.startedAt);
  const events: TimelineEvent[] = [];
  for (const req of sorted) {
    const p = req.path.toLowerCase();
    let kind: TimelineEvent["kind"] = "traffic";
    let label = `${req.method} ${req.template}`;
    if (/login|signin|oauth|token$|session/.test(p) && req.method !== "GET") {
      kind = "login";
      label = `Login ${req.path}`;
    } else if (/refresh/.test(p)) {
      kind = "refresh";
      label = "Token refresh";
    } else if (/logout|signout|revoke/.test(p)) {
      kind = "logout";
      label = "Logout";
    } else if (req.status === 401 || req.status === 403) {
      kind = "error";
      label = `${req.status} ${req.template}`;
    } else if (headerValue(req.requestHeaders, "authorization")) {
      kind = "authz";
      label = `${req.method} ${req.template} → ${req.status || "—"}`;
    }
    events.push({
      at: req.startedAt,
      actor: req.actor,
      kind,
      label,
      detail: `${req.status || "no status"} · ${req.origin || "local"}`,
      requestId: req.id,
    });
  }
  return events;
}

function jsonKeys(text?: string): string[] {
  if (!text) return [];
  try {
    const v = JSON.parse(text) as unknown;
    if (v && typeof v === "object" && !Array.isArray(v)) return Object.keys(v as object).sort();
  } catch {
    /* ignore */
  }
  return [];
}

function diffRows(requests: CapturedRequest[]): DiffRow[] {
  const groups = new Map<string, CapturedRequest[]>();
  for (const r of requests) {
    if (r.method === "PASTE") continue;
    const k = `${r.method} ${r.template}`;
    const list = groups.get(k) ?? [];
    list.push(r);
    groups.set(k, list);
  }
  const rows: DiffRow[] = [];
  for (const [key, list] of groups) {
    const [method, ...rest] = key.split(" ");
    const template = rest.join(" ");
    const a = list.filter((x) => x.actor === "A");
    const b = list.filter((x) => x.actor === "B");
    const aStatuses = [...new Set(a.map((x) => x.status))];
    const bStatuses = [...new Set(b.map((x) => x.status))];
    const aSample = a[0];
    const bSample = b[0];
    let verdict: DiffRow["verdict"] = "same";
    let note = "Same shape";
    if (a.length && !b.length) {
      verdict = "a-only";
      note = "Only actor A hit this route";
    } else if (!a.length && b.length) {
      verdict = "b-only";
      note = "Only actor B hit this route";
    } else {
      const aOk = a.some((x) => x.status >= 200 && x.status < 300);
      const bOk = b.some((x) => x.status >= 200 && x.status < 300);
      const bDenied = b.some((x) => x.status === 401 || x.status === 403);
      const sameObject = a.some(
        (ar) =>
          ar.status >= 200 &&
          ar.status < 300 &&
          pathIds(ar.path).length > 0 &&
          b.some((br) => br.path === ar.path && br.status >= 200 && br.status < 300),
      );
      if (sameObject) {
        verdict = "bola";
        note = "Both actors 2xx on the same object id";
      } else if (aOk && bOk) {
        const aKeys = jsonKeys(aSample?.responseBody).join(",");
        const bKeys = jsonKeys(bSample?.responseBody).join(",");
        const aId = pathIds(aSample?.path ?? "").join(",");
        const bId = pathIds(bSample?.path ?? "").join(",");
        if (aId && bId && aId !== bId && aOk && bOk) {
          verdict = "mixed";
          note = "Both 2xx on different object ids — check ownership";
        }
        if (aId && bId && aId === bId && aSample?.path === bSample?.path) {
          verdict = "bola";
          note = "Both actors 2xx on the same object id";
        } else if (aKeys && bKeys && aKeys === bKeys) {
          note = "Same JSON keys, both 2xx";
        }
      } else if (aOk && bDenied) {
        verdict = "denied";
        note = "A allowed, B denied — looks enforced";
      } else if (aOk && !bOk) {
        verdict = "mixed";
        note = "A 2xx, B not 2xx";
      }
    }
    rows.push({ template, method: method ?? "GET", aStatuses, bStatuses, aSample, bSample, verdict, note });
  }
  return rows.sort((x, y) => x.template.localeCompare(y.template));
}

function findings(ws: Omit<Workspace, "findings">): Finding[] {
  const out: Finding[] = [];
  let n = 0;
  const add = (f: Omit<Finding, "id">) => {
    n += 1;
    out.push({ id: `F${n}`, ...f });
  };

  for (const jwt of ws.jwts) {
    for (const issue of jwt.issues) {
      const sev = issue.includes("none") || issue.includes("unsigned") || issue.includes("jwk") ? "high" : "medium";
      add({
        severity: issue.includes("expired") ? "info" : sev,
        title: `JWT · actor ${jwt.actor}: ${issue.split("—")[0]}`,
        why: issue,
        evidence: [`alg=${jwt.alg ?? "?"}`, `src=${jwt.source}`, `sub=${jwtSubject(jwt) ?? "?"}`],
        how: "Confirm the API rejects alg=none, embedded jwk, and unsigned tokens. Do not send forged tokens at live hosts from this app — export and replay in your proxy against a lab.",
      });
    }
  }

  const cookieSeen = new Set<string>();
  for (const c of ws.cookies) {
    if (c.source !== "set-cookie") continue;
    for (const issue of c.issues) {
      const key = c.actor + c.name + issue;
      if (cookieSeen.has(key)) continue;
      cookieSeen.add(key);
      add({
        severity: issue.includes("HttpOnly") ? "high" : "medium",
        title: `Cookie ${c.name} (${c.actor}): ${issue}`,
        why: issue,
        evidence: [
          `Secure=${c.flags.secure}`,
          `HttpOnly=${c.flags.httpOnly}`,
          `SameSite=${c.flags.sameSite ?? "∅"}`,
        ],
        how: "Session cookies need HttpOnly + Secure + SameSite=Lax/Strict. Fix on the lab app, then re-capture.",
      });
    }
  }

  const ownedA = ownedObjects(ws.requests, ws.jwts, "A");
  const ownedB = ownedObjects(ws.requests, ws.jwts, "B");
  for (const req of ws.requests) {
    if (req.actor !== "B") continue;
    if (req.status < 200 || req.status >= 300) continue;
    const pids = pathIds(req.path);
    const stolen = pids.filter((id) => ownedA.has(id) && !ownedB.has(id));
    if (stolen.length) {
      add({
        severity: "critical",
        title: `BOLA / IDOR · B read A's object ${stolen.join(",")}`,
        why: "Actor B received 2xx on an identifier that only appeared in actor A's session (JWT sub, body ids, or A's URLs).",
        evidence: [`${req.method} ${req.path} → ${req.status}`, `A owns: ${stolen.join(", ")}`],
        template: req.template,
        how: "Authorize on object owner, not on 'is authenticated'. Compare the same request as A vs B in your interceptor.",
      });
    }
  }

  for (const row of ws.diffs) {
    if (row.verdict === "bola") {
      add({
        severity: "critical",
        title: `Same-object 2xx · ${row.method} ${row.template}`,
        why: row.note,
        evidence: [
          `A statuses: ${row.aStatuses.join(",") || "—"}`,
          `B statuses: ${row.bStatuses.join(",") || "—"}`,
          row.aSample?.path ?? "",
          row.bSample?.path ?? "",
        ],
        template: row.template,
        how: "If A and B are different users, this is classic BOLA. Bind the object to session.sub before returning 200.",
      });
    }
  }

  for (const req of ws.requests) {
    const loc = headerValue(req.requestHeaders, "authorization") ?? "";
    if (/[?&](token|jwt|access_token)=/.test(req.url)) {
      add({
        severity: "high",
        title: "Token in query string",
        why: "Secrets in URLs leak via logs, Referer, history.",
        evidence: [req.url.slice(0, 180)],
        template: req.template,
        how: "Move bearer tokens to Authorization header.",
      });
    }
    if (loc.toLowerCase().startsWith("basic ")) {
      add({
        severity: "medium",
        title: "HTTP Basic on captured traffic",
        why: "Basic auth is replayable from the HAR forever until the password changes.",
        evidence: [`${req.method} ${req.path}`],
        how: "Prefer short-lived bearer tokens.",
      });
    }
  }

  for (const l of ws.loot) {
    if (l.kind === "cors" || l.kind === "stack" || l.kind === "mass-assign" || l.kind === "key") {
      add({
        severity: l.severity,
        title: `${l.label} · ${l.where}`,
        why: l.value,
        evidence: [l.kind, l.where],
        how:
          l.kind === "mass-assign"
            ? "In Repeater, toggle one privileged field. If the object mutates, the API binds client-supplied ownership."
            : l.kind === "cors"
              ? "CORS with credentials or * lets a browser origin read authenticated responses."
              : l.kind === "stack"
                ? "Debug traces leak paths and versions — fold into recon, not a live spray from this app."
                : "Treat keys in captures as compromised for the engagement. Rotate in the lab.",
      });
    }
  }

  if (!out.length) {
    add({
      severity: "info",
      title: "No high-confidence auth bug in this capture",
      why: "Heuristics look for alg=none, cookie flags, and B 2xx on A's ids. Absence is not a clean bill of health.",
      evidence: [`${ws.requests.length} requests`],
      how: "Capture the same sensitive routes as both roles, including object ids that belong to A.",
    });
  }

  const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const dedup = new Map<string, Finding>();
  for (const f of out) {
    const k = f.title + f.template;
    if (!dedup.has(k)) dedup.set(k, f);
  }
  return [...dedup.values()].sort((a, b) => rank[a.severity]! - rank[b.severity]!);
}

export function analyze(aRaw: string, bRaw: string, aLabel: string, bLabel: string): Workspace {
  resetParseIds();
  const aReq = [...parseHarLike(aRaw, "A"), ...parseJwtPasted(aRaw, "A")];
  const bReq = [...parseHarLike(bRaw, "B"), ...parseJwtPasted(bRaw, "B")];
  const requests = [...aReq, ...bReq];
  const { jwts, cookies } = collectArtifacts(requests);
  const timeline = buildTimeline(requests);
  const diffs = diffRows(requests);
  const idsA = actorIds(requests, jwts, "A");
  const idsB = actorIds(requests, jwts, "B");
  const ownedA = ownedObjects(requests, jwts, "A");
  const ownedB = ownedObjects(requests, jwts, "B");
  // keep inventory lists inclusive for the loot wordlist
  const idsAAll = [...new Set([...idsA, ...ownedA])];
  const idsBAll = [...new Set([...idsB, ...ownedB])];
  const graph = buildIdGraph(requests, jwts, aLabel, bLabel);
  const loot = harvestLoot(requests);
  const wordlists = buildWordlists(requests, idsAAll, idsBAll);
  const surface = buildSurface(requests);
  const pre: Omit<Workspace, "findings" | "paths" | "replays"> = {
    aLabel,
    bLabel,
    aRaw,
    bRaw,
    requests,
    jwts,
    cookies,
    timeline,
    diffs,
    idsA: idsAAll,
    idsB: idsBAll,
    graph,
    loot,
    wordlists,
    surface,
  };
  const withFindings = { ...pre, findings: findings({ ...pre, paths: [], replays: [] }) };
  const paths = buildPaths(withFindings);
  const replays = buildReplays(withFindings);
  return { ...withFindings, paths, replays };
}
