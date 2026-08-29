import assert from "node:assert/strict";
import { test } from "node:test";
import { corsCredentialedReadRisk, harvestLoot } from "./loot.ts";
import type { CapturedRequest } from "./types.ts";

function req(partial: Partial<CapturedRequest>): CapturedRequest {
  return {
    id: "t",
    actor: "A",
    startedAt: 1,
    method: "GET",
    url: "https://shop.lab/x",
    origin: "https://shop.lab",
    path: "/x",
    template: "/x",
    query: {},
    requestHeaders: [],
    status: 200,
    statusText: "OK",
    responseHeaders: [],
    timeMs: 0,
    ...partial,
  };
}

test("CORS * without credentials on public GET is not loot", () => {
  const loot = harvestLoot([
    req({
      path: "/catalog/9",
      template: "/catalog/{id}",
      responseHeaders: [{ name: "Access-Control-Allow-Origin", value: "*" }],
    }),
  ]);
  assert.equal(loot.filter((l) => l.kind === "cors").length, 0);
});

test("CORS * with credentials is not a credentialed-read finding", () => {
  assert.equal(
    corsCredentialedReadRisk("*", "true")?.kind,
    "invalid-star-credentials",
  );
  const loot = harvestLoot([
    req({
      path: "/api/me",
      template: "/api/me",
      requestHeaders: [{ name: "Authorization", value: "Bearer x.y.z" }],
      responseHeaders: [
        { name: "Access-Control-Allow-Origin", value: "*" },
        { name: "Access-Control-Allow-Credentials", value: "true" },
      ],
    }),
  ]);
  assert.equal(loot.filter((l) => l.kind === "cors").length, 0);
});

test("reflected Origin + credentials is CORS loot", () => {
  const loot = harvestLoot([
    req({
      path: "/api/me",
      template: "/api/me",
      requestHeaders: [
        { name: "Origin", value: "https://evil.example" },
        { name: "Authorization", value: "Bearer x.y.z" },
      ],
      responseHeaders: [
        { name: "Access-Control-Allow-Origin", value: "https://evil.example" },
        { name: "Access-Control-Allow-Credentials", value: "true" },
      ],
    }),
  ]);
  assert.ok(loot.some((l) => l.kind === "cors" && /reflected/i.test(l.value)));
});

test("login POST role field is not mass-assignment", () => {
  const loot = harvestLoot([
    req({
      method: "POST",
      path: "/api/login",
      template: "/api/login",
      requestBody: JSON.stringify({ email: "a@b.c", password: "x", role: "admin" }),
      responseBody: JSON.stringify({ token: "t" }),
    }),
  ]);
  assert.equal(loot.filter((l) => l.kind === "mass-assign").length, 0);
});

test("PATCH /users/me honoring role is mass-assignment", () => {
  const loot = harvestLoot([
    req({
      method: "PATCH",
      path: "/api/users/me",
      template: "/api/users/me",
      requestBody: JSON.stringify({ role: "admin" }),
      responseBody: JSON.stringify({ id: "bob", role: "admin" }),
    }),
  ]);
  assert.ok(loot.some((l) => l.kind === "mass-assign"));
});
