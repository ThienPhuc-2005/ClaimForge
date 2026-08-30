import assert from "node:assert/strict";
import { test } from "node:test";
import {
  applyDraft,
  canCopySignedAsValid,
  createForgeMachine,
  displayToken,
  markSigned,
  outputKind,
  snapshotFromDraft,
} from "./forge-revision.ts";

function draft(over: Partial<ReturnType<typeof snapshotFromDraft>> = {}) {
  return snapshotFromDraft({
    header: '{"alg":"HS256","typ":"JWT"}',
    payload: '{"sub":"alice"}',
    hmacSecret: "lab-secret",
    publicPem: "",
    jwksUrl: "",
    issuer: "https://iss.lab",
    audience: "api",
    ...over,
  });
}

test("fresh machine is unsigned-draft; signed token copy is denied", () => {
  const m = createForgeMachine(draft());
  assert.equal(outputKind(m), "unsigned-draft");
  assert.equal(canCopySignedAsValid(m), false);
});

test("markSigned yields signed-output and allows copy", () => {
  let m = createForgeMachine(draft());
  m = markSigned(m, "aaa.bbb.ccc");
  assert.equal(outputKind(m), "signed-output");
  assert.equal(canCopySignedAsValid(m), true);
  assert.equal(displayToken(m, "unsigned"), "aaa.bbb.ccc");
});

const FIELDS: { name: string; patch: Partial<Parameters<typeof snapshotFromDraft>[0]> }[] = [
  { name: "header", patch: { header: '{"alg":"HS256","typ":"JWT","kid":"x"}' } },
  { name: "payload", patch: { payload: '{"sub":"bob"}' } },
  { name: "alg", patch: { header: '{"alg":"none","typ":"JWT"}' } },
  { name: "hmacSecret", patch: { hmacSecret: "other-secret" } },
  { name: "publicPem", patch: { publicPem: "-----BEGIN PUBLIC KEY-----\nM\n-----END PUBLIC KEY-----" } },
  { name: "jwksUrl", patch: { jwksUrl: "https://lab/.well-known/jwks.json" } },
  { name: "kid", patch: { header: '{"alg":"HS256","typ":"JWT","kid":"rotated"}' } },
  { name: "issuer", patch: { issuer: "https://other.lab" } },
  { name: "audience", patch: { audience: "other-api" } },
];

for (const f of FIELDS) {
  test(`changing ${f.name} after sign makes output stale and blocks signed copy`, () => {
    let m = createForgeMachine(draft());
    m = markSigned(m, "aaa.bbb.SIG");
    m = applyDraft(m, draft(f.patch));
    assert.equal(outputKind(m), "stale-output");
    assert.equal(canCopySignedAsValid(m), false);
    assert.equal(displayToken(m, "unsigned-now"), "unsigned-now");
    assert.equal(m.signedToken, "aaa.bbb.SIG");
  });
}

test("identical draft does not bump revision or stale a signature", () => {
  const snap = draft();
  let m = createForgeMachine(snap);
  m = markSigned(m, "aaa.bbb.ccc");
  const rev = m.revision;
  m = applyDraft(m, draft());
  assert.equal(m.revision, rev);
  assert.equal(outputKind(m), "signed-output");
  assert.equal(canCopySignedAsValid(m), true);
});
