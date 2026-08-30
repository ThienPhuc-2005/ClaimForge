import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { analyze } from "../claimforge/analyze.ts";
import { demoActorA, demoActorB } from "../claimforge/demo.ts";
import { handleLabRequest } from "../lab/engine.ts";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "../../..");
const teamDir = here;

test("team sources do not import platform auth", () => {
  const files = readdirSync(teamDir).filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts"));
  assert.ok(files.length >= 4);
  const banned = [
    "authMiddleware",
    "requireUserId",
    "@/lib/auth/server",
    "@/lib/auth/middleware",
    "../auth/server",
    "../auth/middleware",
    "../auth/verify.server",
  ];
  const importRe = /(?:import(?:\s+type)?(?:[\s\S]*?from)?\s*|import\s*\(|require\s*\()\s*['"][^'"]+/g;
  for (const file of files) {
    const src = readFileSync(join(teamDir, file), "utf8");
    const importLike = (src.match(importRe) ?? []).join("\n");
    for (const token of banned) {
      assert.equal(importLike.includes(token), false, `${file} imports ${token}`);
    }
    if (!file.startsWith("p1-")) {
      for (const token of banned) {
        assert.equal(src.includes(token), false, `${file} mentions ${token}`);
      }
    }
  }
});

test("auth schema stays out of the product glob", () => {
  const entries = readdirSync(join(root, "migrations"));
  assert.equal(entries.includes("0001_auth.sql"), false);
  assert.ok(entries.includes("0003_team_isolation.sql"));
  assert.ok(readdirSync(join(root, "migrations/auth")).includes("0001_auth.sql"));
});

test("solo demo BOLA still confirms after team kernel", () => {
  const ws = analyze(demoActorA(), demoActorB(), "alice", "bob");
  assert.ok(ws.findings.some((f) => /BOLA|IDOR/i.test(f.title) && f.confidence === "confirmed"));
});

test("lab login still issues a token", async () => {
  const res = await handleLabRequest(
    new Request("http://lab.test/api/lab/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "alice@lab.test", password: "demo" }),

    }),
  );
  assert.equal(res.status, 200);
  const body = (await res.json()) as { token?: string };
  assert.equal(typeof body.token, "string");
});
