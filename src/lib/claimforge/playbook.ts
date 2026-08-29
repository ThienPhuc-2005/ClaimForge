import type { AttackPath, CapturedRequest, Finding, HttpHeader, JwtToken, ReplayItem, Workspace } from "./types.ts";
import { bearerOf } from "./loot.ts";
import { mintJwt } from "./jwt.ts";
import { pathIds } from "./ids.ts";

function sh(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

const SKIP_HOP = /^(host|content-length|connection|transfer-encoding|accept-encoding)$/i;
const AUTH_H = /^(authorization|cookie)$/i;

function withoutForeignAuth(sample: CapturedRequest): CapturedRequest {
  return {
    ...sample,
    requestHeaders: sample.requestHeaders.filter((h) => !AUTH_H.test(h.name)),
  };
}

export function curlReplay(sample: CapturedRequest, auth?: { bearer?: string; cookie?: string }): string {
  const parts = ["curl", "-sS", sh(sample.url)];
  const method = sample.method && sample.method !== "GET" ? sample.method : "";
  if (method) parts.splice(2, 0, "-X", method);
  const headers: HttpHeader[] = [...sample.requestHeaders];
  if (auth?.bearer) {
    const i = headers.findIndex((h) => h.name.toLowerCase() === "authorization");
    const h = { name: "Authorization", value: `Bearer ${auth.bearer}` };
    if (i >= 0) headers[i] = h;
    else headers.push(h);
  }
  if (auth?.cookie) {
    const i = headers.findIndex((h) => h.name.toLowerCase() === "cookie");
    const h = { name: "Cookie", value: auth.cookie };
    if (i >= 0) headers[i] = h;
    else headers.push(h);
  }
  for (const h of headers) {
    if (SKIP_HOP.test(h.name)) continue;
    parts.push("-H", sh(`${h.name}: ${h.value}`));
  }
  if (sample.requestBody) parts.push("--data-binary", sh(sample.requestBody));
  return parts.join(" ");
}

function rawHttpFromSample(sample: CapturedRequest, auth?: { bearer?: string; cookie?: string }): string {
  let u: URL;
  try {
    u = new URL(sample.url);
  } catch {
    return `${sample.method} ${sample.url}`;
  }
  const lines = [`${sample.method} ${u.pathname}${u.search} HTTP/1.1`, `Host: ${u.host}`];
  const bearer = auth?.bearer;
  const cookie = auth?.cookie;
  for (const h of sample.requestHeaders) {
    if (SKIP_HOP.test(h.name) || AUTH_H.test(h.name)) continue;
    lines.push(`${h.name}: ${h.value}`);
  }
  if (bearer) lines.push(`Authorization: Bearer ${bearer}`);
  if (cookie) lines.push(`Cookie: ${cookie}`);
  if (sample.requestBody) {
    lines.push("", sample.requestBody);
  } else lines.push("", "");
  return lines.join("\n");
}

function tokenOfActor(reqs: CapturedRequest[]): string | undefined {
  return reqs.map(bearerOf).find(Boolean);
}

export function buildReplays(ws: Pick<Workspace, "requests" | "jwts" | "graph" | "aLabel" | "bLabel">): ReplayItem[] {
  const out: ReplayItem[] = [];
  const aReqs = ws.requests.filter((r) => r.actor === "A" && r.method !== "PASTE");
  const bReqs = ws.requests.filter((r) => r.actor === "B" && r.method !== "PASTE");
  const bTok = tokenOfActor(bReqs);

  const bola = ws.graph.edges.filter((e) => e.bola);
  for (const e of bola) {
    const sample =
      aReqs.find((r) => `${r.method} ${r.path}` === e.via || e.via.endsWith(r.path)) ??
      bReqs.find((r) => `${r.method} ${r.path}` === e.via || e.via.endsWith(r.path));
    if (!sample || !bTok) continue;
    const clean = withoutForeignAuth(sample);
    out.push({
      id: `replay-bola-${out.length}`,
      title: `BOLA · ${ws.bLabel} bearer only on ${e.via}`,
      severity: "critical",
      note: "One actor's bearer, none of the other actor's cookies. Paste into a lab interceptor. ClaimForge does not send it.",
      curl: curlReplay(clean, { bearer: bTok }),
      raw: rawHttpFromSample(clean, { bearer: bTok }),
    });
  }

  const noneJwt = ws.jwts.find((j) => (j.alg ?? "").toLowerCase() === "none" || j.issues.some((i) => i.includes("none")));
  if (noneJwt) {
    const admin = mintJwt({ alg: "none", typ: "JWT" }, { ...noneJwt.payload, role: "admin", is_admin: true });
    const hostReq = [...aReqs, ...bReqs].find((r) => r.path.includes("/admin") || r.template.includes("/me")) ?? aReqs[0];
    if (hostReq) {
      const forged = withoutForeignAuth({
        ...hostReq,
        method: "GET",
        requestBody: undefined,
      });
      out.push({
        id: "replay-none-admin",
        title: "Unsigned JWT · role=admin (forged locally)",
        severity: "high",
        note: "Generated here. Replay only in a lab proxy you control. Heuristic — the live API may still reject alg=none.",
        curl: curlReplay(forged, { bearer: admin }),
        raw: rawHttpFromSample(forged, { bearer: admin }),
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
  const clean = withoutForeignAuth(aObj);
  return {
    id: "replay-swap-id",
    title: `Hypothesis · ${aObj.method} ${aObj.path} with B bearer only`,
    severity: "medium",
    note: "B never hit this path in the capture. Single-actor credential. Test in-scope only.",
    curl: curlReplay(clean, { bearer: bTok }),
    raw: rawHttpFromSample(clean, { bearer: bTok }),
  };
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
  const bolaF = ws.findings.filter((f) => f.confidence === "confirmed" && /BOLA|IDOR/i.test(f.title));
  if (bolaF.length) {
    paths.push({
      id: "path-horizontal",
      title: `Horizontal access · ${ws.bLabel} reads ${ws.aLabel}'s objects`,
      objective: "Reproduce BOLA in a lab proxy with two sessions and one object id. Capture heuristics are not a ship-it report.",
      findingIds: bolaF.map((f) => f.id),
      steps: [
        `Capture login for ${ws.aLabel} and ${ws.bLabel} (two HARs / Burp XML).`,
        "Open ID graph — red edges are foreign object reads (heuristic).",
        `Copy the BOLA curl from Playbook (${ws.bLabel} bearer only + ${ws.aLabel} object URL).`,
        "Replay in your interceptor on the lab. Confirm foreign fields in the body.",
        "File only after the live lab response matches. Missing object-level authorization is the usual fix.",
      ],
    });
  }

  const jwtF = ws.findings.filter((f) => /alg is none|unsigned/i.test(f.why + f.title));
  if (jwtF.length) {
    paths.push({
      id: "path-jwt-none",
      title: "Unsigned JWT · claim tamper",
      objective: "Mint alg=none with elevated role and test admin routes in a lab proxy. Capture alg=none does not prove the API accepts it.",
      findingIds: jwtF.map((f) => f.id),
      steps: [
        "Open Forge, load the unsigned token.",
        "Preset: alg none + role admin.",
        "Copy the minted token. Do not send it from this app.",
        "In your proxy, replace Authorization on /api/admin/* and /api/me.",
        "If admin JSON returns, the API trusts client-signed tokens. If 401, the capture issue did not reproduce.",
      ],
    });
  }

  const mass = ws.loot.filter((l) => l.kind === "mass-assign");
  if (mass.length) {
    paths.push({
      id: "path-mass",
      title: "Mass assignment on write endpoints",
      objective: "Check whether role/price/userId in JSON is honored — the loot row is a hint.",
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
      objective: "403 in this capture is not 403 after claim tamper. Re-test in the lab.",
      findingIds: [],
      steps: [
        ...denied.slice(0, 4).map((d) => `${d.method} ${d.template} denied for B — retry with forged admin JWT in the lab proxy.`),
      ],
    });
  }

  const sessF = ws.findings.filter((f) => /logout/i.test(f.title));
  if (sessF.length) {
    paths.push({
      id: "path-logout",
      title: "Token still valid after logout",
      objective: "Check whether the server revokes the bearer on logout. A later 2xx is a hint, not policy proof outside lab.",
      findingIds: sessF.map((f) => f.id),
      steps: [
        "Capture login, a privileged GET, logout, then the same GET.",
        "If the last GET is 2xx after a 2xx logout, the session may not be on a denylist.",
        "Replay that curl from Playbook on the lab. Do not fire it from this app.",
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
