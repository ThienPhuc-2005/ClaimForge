import assert from "node:assert/strict";
import { test } from "node:test";
import { parseSetCookie } from "./cookies.ts";

test("multiple Set-Cookie in one header split, Expires comma kept", () => {
  const raw =
    "sid=aaa; Path=/; HttpOnly; Secure; SameSite=Lax; Expires=Tue, 19 Jan 2038 03:14:07 GMT, pref=dark; Path=/";
  const cookies = parseSetCookie(raw, "A");
  assert.equal(cookies.length, 2);
  assert.equal(cookies[0]?.name, "sid");
  assert.equal(cookies[0]?.flags.httpOnly, true);
  assert.equal(cookies[0]?.flags.secure, true);
  assert.ok(cookies[0]?.flags.expires?.includes("Tue"));
  assert.equal(cookies[1]?.name, "pref");
});

test("session-like missing flags is an issue; theme cookie is not", () => {
  const sess = parseSetCookie("sid=x; Path=/", "A");
  assert.ok(sess[0]?.issues.some((i) => /HttpOnly/i.test(i)));
  const theme = parseSetCookie("theme=dark; Path=/", "A");
  assert.equal(theme[0]?.issues.length, 0);
  const ga = parseSetCookie("_ga=GA1.1; Path=/", "A");
  assert.equal(ga[0]?.issues.length, 0);
});

test("session cookie with HttpOnly Secure SameSite is clean", () => {
  const c = parseSetCookie("sid=ok; Path=/; HttpOnly; Secure; SameSite=Lax", "B");
  assert.equal(c[0]?.issues.length, 0);
});
