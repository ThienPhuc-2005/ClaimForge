import assert from "node:assert/strict";
import { test } from "node:test";
import { analyze } from "./analyze.ts";
import { demoActorA, demoActorB } from "./demo.ts";
import {
  applyReviewOverrides,
  applyReviewTransition,
  canTransitionReview,
  capSeverity,
  engineReviewState,
  finalizeFinding,
  impactFromReasonCodes,
} from "./review.ts";
import type { Finding } from "./types.ts";

function har(entries: object[]) {
  return JSON.stringify({ log: { version: "1.2", entries } });
}

function jwt(sub: string, alg: "none" | "HS256" = "none") {
  const header =
    alg === "none"
      ? "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
      : "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
  const payload = Buffer.from(JSON.stringify({ sub }), "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return alg === "none" ? `${header}.${payload}.` : `${header}.${payload}.dummysig`;
}

function get(t: string, url: string, status: number, token: string, body: object, extra: Record<string, string> = {}) {
  return {
    startedDateTime: t,
    request: {
      method: "GET",
      url,
      headers: [{ name: "Authorization", value: `Bearer ${token}` }, ...Object.entries(extra).map(([name, value]) => ({ name, value }))],
    },
    response: { status, headers: [], content: { text: JSON.stringify(body) } },
  };
}

test("observation and suspicion cannot be Critical; type name is not impact", () => {
  const none = capSeverity("observation", "critical", impactFromReasonCodes(["JWT_ALG_NONE"]));
  const cookie = capSeverity("observation", "critical", impactFromReasonCodes(["COOKIE_MISSING_HTTPONLY"]));
  const suspect = capSeverity("suspicion", "critical", impactFromReasonCodes(["CROSS_ACTOR_2XX", "MISSING_TRUSTED_OWNERSHIP"]));
  assert.notEqual(none, "critical");
  assert.notEqual(cookie, "critical");
  assert.notEqual(suspect, "critical");
  const bola = capSeverity(
    "confirmed",
    "critical",
    impactFromReasonCodes(["CROSS_ACTOR_2XX", "SERVER_OWNERSHIP_PROOF"]),
  );
  assert.equal(bola, "critical");
});

test("confirmed without ownership+cross-actor is capped off Critical", () => {
  const fake = finalizeFinding({
    severity: "critical",
    confidence: "confirmed",
    title: "BOLA by name only",
    why: "type name",
    evidence: ["x"],
    how: "n/a",
    fingerprint: "bola-name",
    reasonCodes: ["CAPTURE_HEURISTIC_ONLY"],
  });
  assert.notEqual(fake.severity, "critical");
  assert.ok(fake.reasonCodes.includes("IMPACT_NOT_PROVEN"));
});

test("JWT alg=none is Observation, never Confirmed or Critical", () => {
  const a = har([get("2026-08-30T01:00:00.000Z", "https://shop.lab/api/me", 200, jwt("alice"), { id: "alice" })]);
  const ws = analyze(a, "", "alice", "bob");
  const jwtF = ws.findings.filter((f) => /^JWT/.test(f.title));
  assert.ok(jwtF.length >= 1);
  assert.ok(jwtF.every((f) => f.confidence === "observation"));
  assert.ok(jwtF.every((f) => f.severity !== "critical"));
  const noneF = jwtF.filter((f) => /none|unsigned/i.test(f.title + f.why));
  assert.ok(noneF.length >= 1);
  assert.ok(noneF.every((f) => f.reasonCodes.includes("JWT_ALG_NONE") || f.reasonCodes.includes("JWT_UNSIGNED")));
  assert.ok(jwtF.every((f) => f.reviewState === "new"));
});

test("cookie missing HttpOnly is Observation, never Confirmed Critical", () => {
  const a = har([
    {
      startedDateTime: "2026-08-30T01:10:00.000Z",
      request: { method: "GET", url: "https://shop.lab/api/me", headers: [] },
      response: {
        status: 200,
        headers: [{ name: "Set-Cookie", value: "sid=abc12345; Path=/" }],
        content: { text: "{}" },
      },
    },
  ]);
  const ws = analyze(a, "", "alice", "bob");
  const ck = ws.findings.filter((f) => /Cookie/i.test(f.title));
  assert.ok(ck.length >= 1);
  assert.ok(ck.every((f) => f.confidence === "observation"));
  assert.ok(ck.every((f) => f.severity !== "critical"));
  assert.ok(ck.some((f) => f.reasonCodes.includes("COOKIE_MISSING_HTTPONLY")));
});

test("same-object 2xx without ownership is Suspicion medium, not Confirmed Critical", () => {
  const a = har([get("2026-08-30T01:20:00.000Z", "https://shop.lab/api/items/77", 200, jwt("alice"), { id: 77 })]);
  const b = har([get("2026-08-30T01:20:01.000Z", "https://shop.lab/api/items/77", 200, jwt("bob"), { id: 77 })]);
  const ws = analyze(a, b, "alice", "bob");
  const bolaNamed = ws.findings.filter((f) => /BOLA|IDOR|items/i.test(f.title));
  assert.ok(!bolaNamed.some((f) => f.confidence === "confirmed"));
  assert.ok(!bolaNamed.some((f) => f.severity === "critical"));
  const suspect = ws.findings.find((f) => f.confidence === "suspicion");
  assert.ok(suspect);
  assert.equal(suspect!.reviewState, "needs-evidence");
  assert.ok(suspect!.reasonCodes.includes("MISSING_TRUSTED_OWNERSHIP"));
  assert.ok((suspect!.missingEvidence ?? []).length >= 1);
});

test("every engine finding has reason codes and review state", () => {
  const ws = analyze(demoActorA(), demoActorB(), "alice", "bob");
  assert.ok(ws.findings.length >= 1);
  for (const f of ws.findings) {
    assert.ok(f.reasonCodes.length >= 1, f.title);
    assert.ok(f.reviewState, f.title);
    assert.equal(f.reviewState, engineReviewState(f.confidence));
  }
  const bola = ws.findings.filter((f) => f.confidence === "confirmed" && /BOLA/i.test(f.title));
  assert.ok(bola.length >= 1);
  assert.ok(bola.every((f) => f.severity === "critical"));
  assert.ok(bola.every((f) => f.reasonCodes.includes("SERVER_OWNERSHIP_PROOF")));
  assert.ok(bola.every((f) => f.reasonCodes.includes("CROSS_ACTOR_2XX")));
});

test("review transitions: legal path works, illegal path throws", () => {
  assert.equal(canTransitionReview("new", "confirmed"), true);
  assert.equal(canTransitionReview("new", "fixed"), false);
  assert.equal(applyReviewTransition("new", "confirmed"), "confirmed");
  assert.equal(applyReviewTransition("confirmed", "fixed"), "fixed");
  assert.equal(applyReviewTransition("fixed", "retest-passed"), "retest-passed");
  assert.throws(() => applyReviewTransition("new", "retest-passed"));
  assert.throws(() => applyReviewTransition("rejected", "confirmed"));
});

test("analyst review overlay does not change engine confidence", () => {
  const base: Finding[] = [
    {
      id: "F1",
      severity: "medium",
      confidence: "suspicion",
      title: "unproven",
      why: "w",
      evidence: ["e"],
      how: "h",
      fingerprint: "bola-suspect:/api/items/{id}",
      reasonCodes: ["CROSS_ACTOR_2XX", "MISSING_TRUSTED_OWNERSHIP"],
      reviewState: "needs-evidence",
    },
  ];
  const overlaid = applyReviewOverrides(base, { "bola-suspect:/api/items/{id}": "confirmed" });
  assert.equal(overlaid[0]!.reviewState, "confirmed");
  assert.equal(overlaid[0]!.confidence, "suspicion");
  assert.equal(overlaid[0]!.severity, "medium");
});

test("re-analysis restores analyst fixed state by fingerprint", () => {
  const a = har([
    get("2026-08-30T01:30:00.000Z", "https://shop.lab/api/invoices/5512", 200, jwt("alice"), {
      id: 5512,
      ownerId: "alice",
    }),
  ]);
  const b = har([
    get("2026-08-30T01:30:01.000Z", "https://shop.lab/api/invoices/5512", 200, jwt("bob"), {
      id: 5512,
      ownerId: "alice",
    }),
  ]);
  const first = analyze(a, b, "alice", "bob");
  const bola = first.findings.find((f) => f.confidence === "confirmed" && /BOLA/i.test(f.title));
  assert.ok(bola);
  const fp = bola!.fingerprint!;
  const second = analyze(a, b, "alice", "bob");
  const restored = applyReviewOverrides(second.findings, { [fp]: "fixed" });
  const again = restored.find((f) => f.fingerprint === fp);
  assert.equal(again?.reviewState, "fixed");
  assert.equal(again?.confidence, "confirmed");
});
