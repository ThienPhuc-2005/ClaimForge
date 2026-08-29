import assert from "node:assert/strict";
import { test } from "node:test";
import { curlReplay } from "./playbook.ts";
import type { CapturedRequest } from "./types.ts";

test("curl replay keeps method and body, no -k", () => {
  const sample: CapturedRequest = {
    id: "1",
    actor: "A",
    startedAt: 1,
    method: "PATCH",
    url: "https://shop.lab/api/users/me",
    origin: "https://shop.lab",
    path: "/api/users/me",
    template: "/api/users/me",
    query: {},
    requestHeaders: [
      { name: "Content-Type", value: "application/json" },
      { name: "Authorization", value: "Bearer old" },
    ],
    requestBody: '{"role":"admin"}',
    status: 200,
    statusText: "OK",
    responseHeaders: [],
    timeMs: 0,
  };
  const c = curlReplay(sample, { bearer: "newtok" });
  assert.match(c, /curl -sS/);
  assert.doesNotMatch(c, /(^|\s)-k(\s|$)/);
  assert.match(c, /-X PATCH/);
  assert.match(c, /--data-binary/);
  assert.match(c, /role/);
  assert.match(c, /Bearer newtok/);
});
