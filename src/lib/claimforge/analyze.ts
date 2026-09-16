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
import { bolaEvidence, type ReasonCode } from "./evidence.ts";
import { fnv1a64Hex } from "./hash.ts";
import { DEFAULT_POLICY, isDenyStatus, isPrivilegeEscalation, isPrivilegedRole, isSuccessStatus, policyFingerprint, type AnalysisPolicy } from "./policy.ts";
import { ENGINE_VERSION, RULE_VERSION } from "./versions.ts";
import { buildIdGraph } from "./graph.ts";
import { buildSurface, buildWordlists, harvestLoot } from "./loot.ts";
import { buildPaths, buildReplays } from "./playbook.ts";
import { classifySameObject, looksPublicOrShared, sameObjectHits, strongestClass } from "./bola.ts";
import { classifyTimeline, tokensAliveAfterLogout } from "./session.ts";
import { brokenFunctionLevelAuthz } from "./bfla.ts";
import { csrfExposures } from "./csrf.ts";
import { refreshTokenReuse } from "./refresh.ts";
import { openRedirects } from "./redirect.ts";
import { buildSpecCoverage } from "./spec.ts";
import { jwtIssueKind, mergeFindings } from "./dedup.ts";
import {
  cookieReasonCode,
  finalizeFinding,
  jwtReasonCodes,
  lootReasonCode,
  minSeverity,
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
  const policy = ws.policy ?? DEFAULT_POLICY;

  for (const jwt of ws.jwts) {
    const kinds = new Map<string, string[]>();
    for (const issue of jwt.issues) {
      const kind = jwtIssueKind(issue);
      const list = kinds.get(kind) ?? [];
      list.push(issue);
      kinds.set(kind, list);
    }
    for (const [kind, issues] of kinds) {
      if (kind === "priv-role") {
        const role = String(jwt.payload.role ?? jwt.payload.roles ?? jwt.payload.is_admin ?? "");
        if (!isPrivilegedRole(policy, role)) continue;
      }
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
      const codes: ReasonCode[] = [lootReasonCode(l.kind, l.value)];
      let confidence: Finding["confidence"] =
        l.kind === "cors" && /reflected/i.test(l.value) ? "suspicion" : "observation";
      let severity = l.severity;
      if (l.kind === "mass-assign") {
        const actorRole = String(
          ws.jwts.find((j) => j.actor === l.actor)?.payload.role ??
            ws.jwts.find((j) => j.actor === l.actor)?.payload.roles ??
            "",
        );
        const req = ws.requests.find((r) => `${r.actor} ${r.method} ${r.path}` === l.where);
        let assigned: string[] = [];
        try {
          const body = req?.requestBody ? (JSON.parse(req.requestBody) as Record<string, unknown>) : null;
          if (body && typeof body === "object") {
            assigned = l.value
              .split(",")
              .map((k) => String(body[k.trim()] ?? k.trim()))
              .filter(Boolean);
          }
        } catch {
          assigned = l.value.split(",").map((s) => s.trim()).filter(Boolean);
        }
        if (assigned.some((v) => isPrivilegeEscalation(policy, actorRole, v))) {
          codes.push("ROLE_ESCALATION");
          confidence = "confirmed";
          severity = minSeverity(severity, "high");
        }
      }
      add({
        severity,
        confidence,
        title: `${l.label} · ${l.where}`,
        why: l.value,
        evidence: [l.kind, l.where],
        how:
          l.kind === "mass-assign"
            ? codes.includes("ROLE_ESCALATION")
              ? "The write honored a role that is strictly above the actor in the declared hierarchy. Confirm the API binds role from the session, not the body."
              : "In Repeater, toggle one privileged field. If the object mutates, the API binds client-supplied ownership."
            : l.kind === "cors"
              ? corsHow(l.value)
              : l.kind === "stack"
                ? "Debug traces leak paths and versions — fold into recon, not a live spray from this app."
                : "Treat keys in captures as compromised for the engagement. Rotate in the lab.",
        fingerprint: `loot:${l.kind}:${l.where}:${l.label}`,
        reasonCodes: codes,
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

  for (const hit of brokenFunctionLevelAuthz(ws.requests, ws.jwts, policy)) {
    add({
      severity: hit.confidence === "confirmed" ? "high" : "medium",
      confidence: hit.confidence,
      title: `BFLA · actor ${hit.actor} (${hit.actorRole}) on admin function ${hit.method} ${hit.template}`,
      why: hit.enforcementObserved
        ? `${hit.method} ${hit.path} returned ${hit.status} for a ${hit.roleVerified ? "verified " : ""}non-privileged actor, while the same function was denied elsewhere in the capture — the function is enforced and this call bypassed it.`
        : `${hit.method} ${hit.path} returned ${hit.status} for actor ${hit.actor}, whose role does not look privileged, on an administrative function.`,
      evidence: [
        `${hit.method} ${hit.path} → ${hit.status}`,
        `role=${hit.actorRole}${hit.roleVerified ? " (verified)" : " (unverified)"}`,
        hit.enforcementObserved ? "same function denied elsewhere" : "no deny observed on this function",
      ],
      template: hit.template,
      how: "Enforce role/permission on the function server-side, not just object ownership. Replay the same request as the low-privilege actor in a lab proxy to confirm.",
      fingerprint: `bfla:${hit.actor}:${hit.method}:${hit.template}`,
      reasonCodes: hit.reasonCodes,
      reviewState: hit.confidence === "confirmed" ? "new" : "needs-evidence",
    });
  }

  for (const hit of csrfExposures(ws.requests, ws.cookies, policy)) {
    const none = hit.sameSite === "none";
    add({
      severity: none ? "medium" : "low",
      confidence: hit.confidence,
      title: `CSRF-exposed ${hit.method} ${hit.template}`,
      why: none
        ? `${hit.method} ${hit.path} changes state using cookie auth (${hit.cookieNames.join(", ")}) with SameSite=None and no anti-CSRF token — a cross-site page could forge it.`
        : `${hit.method} ${hit.path} changes state using cookie auth (${hit.cookieNames.join(", ")}) and no anti-CSRF token. SameSite was not observed; the modern Lax default blocks cross-site POST, but legacy/relaxed contexts do not.`,
      evidence: [
        `${hit.method} ${hit.path} → ${hit.status}`,
        `cookies=${hit.cookieNames.join(", ")}`,
        none ? "SameSite=None" : "SameSite not observed (Lax default)",
      ],
      template: hit.template,
      how: "Require a per-session anti-CSRF token (or SameSite=Lax/Strict plus a custom request header). Confirm by forging the request cross-site in a browser.",
      fingerprint: `csrf:${hit.method}:${hit.template}`,
      reasonCodes: hit.reasonCodes,
    });
  }

  for (const hit of refreshTokenReuse(ws.requests, policy)) {
    add({
      severity: hit.rotationObserved ? "high" : "medium",
      confidence: hit.confidence,
      title: hit.rotationObserved
        ? `Rotated refresh token accepted again · actor ${hit.actor}`
        : `Refresh token replayed · actor ${hit.actor}`,
      why: hit.rotationObserved
        ? `A refresh token the server had rotated away (a different token was issued in its place) was accepted again with ${hit.status} at ${hit.method} ${hit.path}. Rotation may not be enforced.`
        : `The same refresh token was presented on two separate refresh requests and returned ${hit.status}. No rotation was observed in this capture, so reuse may be by design.`,
      evidence: [
        `${hit.method} ${hit.path} → ${hit.status}`,
        `refresh ${hit.tokenHint}`,
        hit.lab ? "lab host" : "outside lab",
        hit.rotationObserved ? "rotation observed" : "rotation not observed",
      ],
      template: hit.template,
      how: "A short reuse/leeway window is legitimate (RFC 9700). Confirm in a lab that the old token still works well past any grace window; on true reuse, revoke the whole token family (breach detection).",
      fingerprint: `refresh:${hit.actor}:${hit.rotationObserved ? "reuse" : "replay"}:${hit.tokenHint}`,
      reasonCodes: hit.reasonCodes,
    });
  }

  for (const hit of openRedirects(ws.requests)) {
    add({
      severity: hit.severity,
      confidence: hit.confidence,
      title: `Open redirect · ${hit.method} ${hit.template} (${hit.param})`,
      why: hit.reflected
        ? `The server redirected (${hit.status}) to an ${hit.dangerous ? "unsafe-scheme" : "off-origin"} target taken from the client-controlled '${hit.param}' parameter${hit.location ? `: ${hit.location}` : ""}.`
        : `The '${hit.param}' parameter carries an ${hit.dangerous ? "unsafe-scheme" : "off-origin"} redirect target (${hit.target}); no honoring redirect was seen in this capture.`,
      evidence: [
        `${hit.method} ${hit.path} → ${hit.status}`,
        `${hit.param}=${hit.target}`,
        hit.location ? `Location: ${hit.location}` : "no Location observed",
      ],
      template: hit.template,
      how: "Allowlist redirect targets server-side (relative paths or a fixed host set). In a lab, set the parameter to an attacker origin and confirm the browser is sent there. OAuth redirect_uri must be matched against registered values.",
      fingerprint: `open-redirect:${hit.method}:${hit.template}:${hit.param}`,
      reasonCodes: hit.reasonCodes,
    });
  }

  const spec = ws.specCoverage;
  if (spec && !spec.error && spec.declaredCount) {
    if (spec.untested.length) {
      const interesting = spec.untested.filter((o) => o.secured || o.write);
      add({
        severity: "info",
        confidence: "observation",
        title: `Spec coverage: ${spec.coveredCount}/${spec.declaredCount} declared endpoints exercised`,
        why: `${spec.untested.length} declared endpoint(s) were never seen in the capture (${interesting.length} security-relevant). Untested endpoints are blind spots, not proof of a bug.`,
        evidence: (interesting.length ? interesting : spec.untested)
          .slice(0, 8)
          .map((o) => `${o.method} ${o.path}${o.secured ? " [auth]" : ""}${o.write ? " [write]" : ""}`),
        how: "Capture the untested routes — especially the secured and write ones — as both actors, then re-run.",
        fingerprint: "spec:untested",
        reasonCodes: ["SPEC_ENDPOINT_UNTESTED"],
      });
    }
    if (spec.shadow.length) {
      add({
        severity: "low",
        confidence: "observation",
        title: `${spec.shadow.length} undocumented endpoint(s) in traffic`,
        why: "Routes seen in the capture are not declared in the spec — shadow/undocumented API is a common source of un-reviewed authorization.",
        evidence: spec.shadow.slice(0, 8).map((s) => `${s.method} ${s.template} [${s.statuses.join(",") || "—"}]`),
        how: "Confirm these routes are intended and covered by the same authorization as the documented ones.",
        fingerprint: "spec:shadow",
        reasonCodes: ["SPEC_SHADOW_ENDPOINT"],
      });
    }
  }

  const tr = ws.truncation;
  if (tr && (tr.droppedA || tr.droppedB)) {
    add({
      severity: "medium",
      confidence: "observation",
      title: `Capture truncated — ${tr.droppedA + tr.droppedB} request(s) not analyzed`,
      why: `Only the first ${tr.perActorLimit} requests per actor are analyzed (A: ${tr.droppedA} dropped of ${tr.totalA}; B: ${tr.droppedB} dropped of ${tr.totalB}). Findings do not cover the dropped traffic.`,
      evidence: [
        `A ${tr.totalA - tr.droppedA}/${tr.totalA}`,
        `B ${tr.totalB - tr.droppedB}/${tr.totalB}`,
        `limit ${tr.perActorLimit}/actor`,
      ],
      how: "Split the capture into focused per-feature sessions so no requests are dropped, then re-run each.",
      fingerprint: "capture:truncated",
      reasonCodes: ["CAPTURE_TRUNCATED"],
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
  specRaw = "",
): Workspace {
  resetParseIds();
  const aParsed = parseActorInput(aRaw, "A");
  const bParsed = parseActorInput(bRaw, "B");
  const aReq = slimActor(aParsed.requests);
  const bReq = slimActor(bParsed.requests);
  const requests = [...aReq, ...bReq];
  const droppedA = Math.max(0, aParsed.requests.length - aReq.length);
  const droppedB = Math.max(0, bParsed.requests.length - bReq.length);
  const truncation =
    droppedA || droppedB
      ? {
          totalA: aParsed.requests.length,
          totalB: bParsed.requests.length,
          droppedA,
          droppedB,
          perActorLimit: MAX_REQUESTS_PER_ACTOR,
        }
      : undefined;
  const specCoverage = buildSpecCoverage(specRaw, requests);
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
  const inputHash = fnv1a64Hex(`${aRaw}\n${bRaw}\n${aLabel}\n${bLabel}\n${policyFingerprint(policy)}\n${specRaw}`);
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
    specCoverage,
    truncation,
  };
  const withFindings = { ...pre, findings: findings({ ...pre, paths: [], replays: [], resultHash: "" }) };
  const paths = buildPaths(withFindings);
  const replays = buildReplays(withFindings);
  const resultHash = fnv1a64Hex(
    `${ENGINE_VERSION}|${RULE_VERSION}|${policyFingerprint(policy)}|${inputHash}|${withFindings.findings.map((f) => f.id).join(",")}`,
  );
  return { ...withFindings, paths, replays, resultHash };
}
