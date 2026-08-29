import assert from "node:assert/strict";
import { test } from "node:test";
import { extractJwtStrings, inspectJwt, mintJwt } from "./jwt.ts";
import { analyze } from "./analyze.ts";

const HS256 = mintJwt(
  { alg: "HS256", typ: "JWT" },
  { sub: "alice", iat: 1_700_000_000, exp: 4_100_000_000 },
  "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
);

test("signed HS256 is one token, not an extra unsigned prefix", () => {
  const found = extractJwtStrings(`Authorization: Bearer ${HS256}`);
  assert.deepEqual(found, [HS256]);
  const ins = inspectJwt(found[0]!, "A", "auth");
  assert.equal(ins?.alg, "HS256");
  assert.equal(ins?.parts, 3);
  assert.ok(!ins?.issues.some((i) => /unsigned/i.test(i)));
});

test("true two-part alg=none still extracts as unsigned", () => {
  const none = mintJwt({ alg: "none", typ: "JWT" }, { sub: "bob" }).replace(/\.$/, "");
  const found = extractJwtStrings(none);
  assert.deepEqual(found, [none]);
  const ins = inspectJwt(found[0]!, "A", "paste");
  assert.ok(ins?.issues.some((i) => /unsigned/i.test(i)));
});

test("analyzer does not flag a valid HS256 as unsigned", () => {
  const har = JSON.stringify({
    log: {
      entries: [
        {
          startedDateTime: "2026-08-29T03:00:00.000Z",
          request: {
            method: "GET",
            url: "https://lab.local/api/me",
            headers: [{ name: "Authorization", value: `Bearer ${HS256}` }],
          },
          response: { status: 200, headers: [], content: { text: "{\"ok\":true}" } },
        },
      ],
    },
  });
  const ws = analyze(har, "", "alice", "bob");
  assert.equal(ws.jwts.length, 1);
  assert.equal(ws.jwts[0]?.alg, "HS256");
  assert.equal(ws.jwts[0]?.parts, 3);
  assert.ok(!ws.jwts[0]?.issues.some((i) => /unsigned/i.test(i)));
  assert.ok(!ws.findings.some((f) => /unsigned/i.test(f.title) || /unsigned/i.test(f.why)));
});
