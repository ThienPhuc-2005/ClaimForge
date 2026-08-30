import type {
  CapturedRequest,
  CookieRecord,
  DiffRow,
  Finding,
  JwtToken,
  TimelineEvent,
  Workspace,
} from "./types.ts";
import { headerValue, headerValues, parseCookieHeader, parseSetCookie } from "./cookies.ts";
import { extractJwtStrings, inspectJwt, jwtSubject } from "./jwt.ts";
import { parseActorInput, resetParseIds } from "./parse.ts";
import { MAX_BODY_CHARS, MAX_REQUESTS_PER_ACTOR } from "./limits.ts";
import { actorIds, ownedObjects, pathIds } from "./ids.ts";
import { bolaEvidence } from "./evidence.ts";
import { fnv1a64Hex } from "./hash.ts";
import { DEFAULT_POLICY, isDenyStatus, isSuccessStatus, policyFingerprint, type AnalysisPolicy } from "./policy.ts";
import { ENGINE_VERSION, RULE_VERSION } from "./versions.ts";
import { buildIdGraph } from "./graph.ts";
import { buildSurface, buildWordlists, harvestLoot } from "./loot.ts";
import { buildPaths, buildReplays } from "./playbook.ts";
import { classifySameObject, looksPublicOrShared, sameObjectHits, strongestClass } from "./bola.ts";
import { classifyTimeline, tokensAliveAfterLogout } from "./session.ts";
import { jwtIssueKind, mergeFindings } from "./dedup.ts";
import {
  cookieReasonCode,
  finalizeFinding,
  jwtReasonCodes,
  lootReasonCode,
  type FindingDraft,
} from "./review.ts";

function trimBody(s?: string): string | undefined {
  if (s == null || s.length <= MAX_BODY_CHARS) return s;
  return s.slice(0, MAX_BODY_CHARS);
}

function slimActor(reqs: CapturedRequest[]): CapturedRequest[] {
  const cut = reqs.length > MAX_REQUESTS_PER_ACTOR ? reqs.slice(0, MAX_REQUESTS_PER_ACTOR) : reqs;
  return cut.map((r) => ({
    ...r,
    requestBody: trimBody(r.requestBody),
    responseBody: trimBody(r.responseBody),
  }));
}

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
    for (const sc of headerValues(req.responseHeaders, "set-cookie")) {
      cookies.push(...parseSetCookie(sc, req.actor));
    }
  }
  return { jwts, cookies };
}

function buildTimeline(requests: CapturedRequest[], policy: AnalysisPolicy = DEFAULT_POLICY): TimelineEvent[] {
  const sorted = [...requests].sort((a, b) => a.startedAt - b.startedAt);
  const events: TimelineEvent[] = [];
  for (const req of sorted) {
    if (req.method === "PASTE") continue;
    const { kind, label } = classifyTimeline(req, policy);
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

function diffRows(
  requests: CapturedRequest[],
  ownedA: Set<string>,
  ownedB: Set<string>,
  policy: AnalysisPolicy,
): DiffRow[] {
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
      const aOk = a.some((x) => isSuccessStatus(x.status, policy));
      const bOk = b.some((x) => isSuccessStatus(x.status, policy));
      const bDenied = b.some((x) => isDenyStatus(x.status, policy));
      const pairs = sameObjectHits(a, b);
      const classes = pairs.map(([ar, br]) => {
        const id = pathIds(ar.path)[0] ?? "";
        return classifySameObject(id, ar.path, [ar.responseBody, br.responseBody], ownedA, ownedB, policy);
      });
      const top = strongestClass(classes);
      if (top === "confirmed") {
        verdict = "bola";
        note = "Confirmed BOLA: trusted server-response ownership + B 2xx on A's object";
      } else if (top === "observation") {
        verdict = "shared";
        note = "Both 2xx on a public/shared-looking resource — usually not IDOR; still check object ACL";
      } else if (top === "suspicion") {
        verdict = "suspect";
        note = "Suspicion: both 2xx on the same id, no ownership proof";
      } else if (aOk && bOk) {
        const aKeys = jsonKeys(aSample?.responseBody).join(",");
        const bKeys = jsonKeys(bSample?.responseBody).join(",");
        const aId = pathIds(aSample?.path ?? "").join(",");
        const bId = pathIds(bSample?.path ?? "").join(",");
        if (aId && bId && aId !== bId) {
          verdict = "mixed";
          note = "Both 2xx on different object ids — check ownership";
        } else if (aKeys && bKeys && aKeys === bKeys) {
          note = "Same JSON keys, both 2xx";
        }
      } else if (aOk && bDenied) {
        verdict = "denied";
        note = "A allowed, B denied — this capture looks enforced; not a proof of the whole API";
      } else if (aOk && !bOk) {
        verdict = "mixed";
        note = "A 2xx, B not 2xx";
      }
    }
    rows.push({ template, method: method ?? "GET", aStatuses, bStatuses, aSample, bSample, verdict, note });
  }
  return rows.sort((x, y) => x.template.localeCompare(y.template));
}

function corsHow(value: string): string {
  if (/reflected Origin/i.test(value)) {
    return "Reflected ACAO plus Access-Control-Allow-Credentials can let that origin read authenticated responses. ACAO * with credentials is invalid and is not this bug.";
  }
  return "Wildcard ACAO without credentials is not a credentialed-read bug. Browsers reject ACAO * + credentials=true.";
}

function findings(ws: Omit<Workspace, "findings">): Finding[] {
  const out: Finding[] = [];
  let n = 0;
  const add = (f: FindingDraft) => {
    n += 1;
    out.push({ id: `F${n}`, ...finalizeFinding(f) });
  };

  for (const jwt of ws.jwts) {
    const kinds = new Map<string, string[]>();
    for (const issue of jwt.issues) {
      const kind = jwtIssueKind(issue);
      const list = kinds.get(kind) ?? [];
      list.push(issue);
      kinds.set(kind, list);
    }
    for (const [kind, issues] of kinds) {
      const infoOnly = /iss|aud|lifetime/.test(kind);
      const sev: Finding["severity"] =
        kind === "alg-none" || kind === "key-injection" ? "high" : infoOnly ? "info" : "medium";
      add({
        severity: sev,
        confidence: "observation",
        title: `JWT · actor ${jwt.actor}: ${issues[0]!.split("—")[0]}`,
        why: issues.join("; "),
        evidence: [`alg=${jwt.alg ?? "?"}`, `src=${jwt.source}`, `sub=${jwtSubject(jwt) ?? "?"}`],
        how: "This is a capture heuristic (alg=none / embedded jwk / unsigned). Confirm the API rejects those in a lab proxy. Do not send forged tokens at live hosts from this app.",
        fingerprint: `jwt:${jwt.actor}:${kind}`,
        reasonCodes: jwtReasonCodes(kind, issues),
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
        confidence: "observation",
        title: `Cookie ${c.name} (${c.actor}): ${issue}`,
        why: issue,
        evidence: [
          `Secure=${c.flags.secure}`,
          `HttpOnly=${c.flags.httpOnly}`,
          `SameSite=${c.flags.sameSite ?? "∅"}`,
        ],
        how: "Session cookies need HttpOnly + Secure + SameSite=Lax/Strict. Fix on the lab app, then re-capture.",
        fingerprint: `cookie:${c.actor}:${c.name}:${issue}`,
        reasonCodes: [cookieReasonCode(issue)],
      });
    }
  }

  const ownOpts = {
    policy: ws.policy ?? DEFAULT_POLICY,
    declaredLabels: { A: ws.aLabel, B: ws.bLabel } as const,
  };
  const ownedA = ownedObjects(ws.requests, ws.jwts, "A", ws.cookies, ownOpts);
  const ownedB = ownedObjects(ws.requests, ws.jwts, "B", ws.cookies, ownOpts);
  for (const req of ws.requests) {
    if (req.actor !== "B") continue;
    if (!isSuccessStatus(req.status, ownOpts.policy)) continue;
    const pids = pathIds(req.path);
    const stolen = pids.filter(
      (id) => ownedA.has(id) && !ownedB.has(id) && !looksPublicOrShared(req.path, [req.responseBody], ownOpts.policy),
    );
    if (stolen.length) {
      add({
        severity: "critical",
        confidence: "confirmed",
        title: `BOLA / IDOR · B read A's object ${stolen.join(",")}`,
        why: "Server-response ownership (ownerId / inventory) plus analyst actor map, not request body or an unverified JWT sub, ties the object to A, and B still received 2xx.",
        evidence: [`${req.method} ${req.path} → ${req.status}`, `A owns: ${stolen.join(", ")}`],
        template: req.template,
        how: "Heuristic. Authorize on object owner, not on 'is authenticated'. Compare the same request as A vs B in your interceptor.",
        fingerprint: `bola:${req.template ?? req.path}`,
        reasonCodes: ["CROSS_ACTOR_2XX", "SERVER_OWNERSHIP_PROOF"],
        reviewState: "new",
        canonical: bolaEvidence({
          policyVersion: ownOpts.policy.version,
          actor: "B",
          endpoint: req.template || req.path,
          ownershipSource: "response-field",
          ownershipTrusted: true,
          ownershipReason: "response owner field matched analyst-declared or verified identity",
          identityProvenance: ["analyst-actor-map"],
          captureIds: [req.id],
          reasonCodes: ["CROSS_ACTOR_2XX", "SERVER_OWNERSHIP_PROOF"],
        }),
      });
    }
  }

  for (const row of ws.diffs) {
    if (row.verdict === "bola") {
      add({
        severity: "critical",
        confidence: "confirmed",
        title: `BOLA / IDOR · ${row.method} ${row.template}`,
        why: row.note,
        evidence: [
          `A statuses: ${row.aStatuses.join(",") || "—"}`,
          `B statuses: ${row.bStatuses.join(",") || "—"}`,
          row.aSample?.path ?? "",
          row.bSample?.path ?? "",
        ],
        template: row.template,
        how: "Heuristic. Bind the object to session.sub before returning 200. Replay B's token on A's object in a lab proxy, then file.",
        fingerprint: `bola:${row.template}`,
        reasonCodes: ["CROSS_ACTOR_2XX", "SERVER_OWNERSHIP_PROOF"],
      });
    } else if (row.verdict === "suspect") {
      add({
        severity: "medium",
        confidence: "suspicion",
        title: `Same-object 2xx (unproven) · ${row.method} ${row.template}`,
        why: row.note,
        evidence: [
          `A statuses: ${row.aStatuses.join(",") || "—"}`,
          `B statuses: ${row.bStatuses.join(",") || "—"}`,
          row.aSample?.path ?? "",
        ],
        template: row.template,
        how: "Capture a body with ownerId/userId, or an A-only inventory listing this id, before calling it BOLA.",
        fingerprint: `bola-suspect:${row.template}`,
        reasonCodes: ["CROSS_ACTOR_2XX", "MISSING_TRUSTED_OWNERSHIP"],
        missingEvidence: ["trusted server ownership proof (ownerId / inventory)"],
      });
    } else if (row.verdict === "shared") {
      add({
        severity: "info",
        confidence: "observation",
        title: `Public/shared resource · ${row.method} ${row.template}`,
        why: row.note,
        evidence: [row.aSample?.path ?? "", row.bSample?.path ?? ""],
        template: row.template,
        how: "Both roles 2xx on a catalog/public/shared object is often expected. Do not file as IDOR from this row alone.",
        fingerprint: `shared:${row.template}`,
        reasonCodes: ["PUBLIC_OR_SHARED_ROUTE"],
      });
    }
  }

  for (const req of ws.requests) {
    const loc = headerValue(req.requestHeaders, "authorization") ?? "";
    if (/[?&](token|jwt|access_token)=/.test(req.url)) {
      add({
        severity: "high",
        confidence: "observation",
        title: "Token in query string",
        why: "Secrets in URLs leak via logs, Referer, history.",
        evidence: [req.url.slice(0, 180)],
        template: req.template,
        how: "Move bearer tokens to Authorization header.",
        fingerprint: `token-query:${req.template}`,
        reasonCodes: ["TOKEN_IN_QUERY"],
      });
    }
    if (loc.toLowerCase().startsWith("basic ")) {
      add({
        severity: "medium",
        confidence: "observation",
        title: "HTTP Basic on captured traffic",
        why: "Basic auth is replayable from the HAR forever until the password changes.",
        evidence: [`${req.method} ${req.path}`],
        how: "Prefer short-lived bearer tokens.",
        fingerprint: `basic:${req.template}`,
        reasonCodes: ["HTTP_BASIC"],
      });
    }
  }

  for (const l of ws.loot) {
    if (l.kind === "cors" || l.kind === "stack" || l.kind === "mass-assign" || l.kind === "key") {
      add({
        severity: l.severity,
        confidence: l.kind === "cors" && /reflected/i.test(l.value) ? "suspicion" : "observation",
        title: `${l.label} · ${l.where}`,
        why: l.value,
        evidence: [l.kind, l.where],
        how:
          l.kind === "mass-assign"
            ? "In Repeater, toggle one privileged field. If the object mutates, the API binds client-supplied ownership."
            : l.kind === "cors"
              ? corsHow(l.value)
              : l.kind === "stack"
                ? "Debug traces leak paths and versions — fold into recon, not a live spray from this app."
                : "Treat keys in captures as compromised for the engagement. Rotate in the lab.",
        fingerprint: `loot:${l.kind}:${l.where}:${l.label}`,
        reasonCodes: [lootReasonCode(l.kind, l.value)],
      });
    }
  }

  for (const hit of tokensAliveAfterLogout(ws.requests, ws.policy)) {
    add({
      severity: hit.confidence === "confirmed" ? "high" : "medium",
      confidence: hit.confidence,
      title: `Session lives after logout · actor ${hit.actor}`,
      why: hit.logoutOk
        ? `${hit.method} ${hit.path} still returned ${hit.status} with the same ${hit.credentialKind} that was sent on logout.`
        : `${hit.method} ${hit.path} still returned ${hit.status} after a logout-shaped request — logout success was not observed, so this is not confirmed.`,
      evidence: [`${hit.method} ${hit.path}`, hit.tokenHint, hit.lab ? "lab host" : "outside lab"],
      template: hit.path,
      how: hit.lab
        ? "Invalidate only the session bound to the credentials on the logout request. Sibling devices must stay valid."
        : "Outside lab this stays Suspicion until the app's logout policy (server revoke / jti denylist) is evidenced.",
      fingerprint: `logout:${hit.actor}:${hit.credentialKind}:${hit.tokenHint}`,
      reasonCodes: hit.reasonCodes,
      reviewState: hit.confidence === "confirmed" ? "new" : "needs-evidence",
    });
  }

  if (!out.length && !ws.requests.length) return [];

  if (!out.length) {
    add({
      severity: "info",
      confidence: "observation",
      title: "No high-confidence auth bug in this capture",
      why: "Heuristics look for alg=none, cookie flags, and B 2xx on A's ids. Absence is not a clean bill of health.",
      evidence: [`${ws.requests.length} requests`],
      how: "Capture the same sensitive routes as both roles, including object ids that belong to A.",
      fingerprint: "none",
      reasonCodes: ["NO_FINDING"],
    });
  }

  return mergeFindings(out);
}
export function analyze(
  aRaw: string,
  bRaw: string,
  aLabel: string,
  bLabel: string,
  policy: AnalysisPolicy = DEFAULT_POLICY,
): Workspace {
  resetParseIds();
  const aParsed = parseActorInput(aRaw, "A");
  const bParsed = parseActorInput(bRaw, "B");
  const aReq = slimActor(aParsed.requests);
  const bReq = slimActor(bParsed.requests);
  const requests = [...aReq, ...bReq];
  const { jwts, cookies } = collectArtifacts(requests);
  const timeline = buildTimeline(requests, policy);
  const ownOpts = { policy, declaredLabels: { A: aLabel, B: bLabel } as const };
  const ownedA = ownedObjects(requests, jwts, "A", cookies, ownOpts);
  const ownedB = ownedObjects(requests, jwts, "B", cookies, ownOpts);
  const diffs = diffRows(requests, ownedA, ownedB, policy);
  const idsA = actorIds(requests, jwts, "A");
  const idsB = actorIds(requests, jwts, "B");
  const idsAAll = [...new Set([...idsA, ...ownedA])];
  const idsBAll = [...new Set([...idsB, ...ownedB])];
  const graph = buildIdGraph(requests, jwts, aLabel, bLabel);
  const loot = harvestLoot(requests);
  const wordlists = buildWordlists(requests, idsAAll, idsBAll);
  const surface = buildSurface(requests);
  const inputHash = fnv1a64Hex(`${aRaw}\n${bRaw}\n${aLabel}\n${bLabel}\n${policyFingerprint(policy)}`);
  const pre: Omit<Workspace, "findings" | "paths" | "replays" | "resultHash"> = {
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
    parseErrorA: aParsed.error,
    parseErrorB: bParsed.error,
    engineVersion: ENGINE_VERSION,
    ruleVersion: RULE_VERSION,
    policyVersion: policy.version,
    inputHash,
    policy,
  };
  const withFindings = { ...pre, findings: findings({ ...pre, paths: [], replays: [], resultHash: "" }) };
  const paths = buildPaths(withFindings);
  const replays = buildReplays(withFindings);
  const resultHash = fnv1a64Hex(
    `${ENGINE_VERSION}|${RULE_VERSION}|${policyFingerprint(policy)}|${inputHash}|${withFindings.findings.map((f) => f.id).join(",")}`,
  );
  return { ...withFindings, paths, replays, resultHash };
}
