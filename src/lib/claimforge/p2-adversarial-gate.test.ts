import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { P2_GATES, P2_ITEMS } from "./p2-gates.ts";
import type { ReasonCode } from "./evidence.ts";

const here = dirname(fileURLToPath(import.meta.url));

test("every P2 family has at least one gate and a real evidence test file", () => {
  for (const item of P2_ITEMS) {
    const gates = P2_GATES.filter((g) => g.p2 === item);
    assert.ok(gates.length >= 1, `missing gate for ${item}`);
    for (const g of gates) {
      const file = g.evidenceTest.split(":")[0]!;
      assert.ok(existsSync(join(here, file)), `evidence test missing: ${file}`);
    }
  }
});

test("gate rows are well-formed (before != after, non-empty fields)", () => {
  for (const g of P2_GATES) {
    assert.ok(g.id && g.bug && g.before && g.after && g.evidenceTest);
    assert.notEqual(g.before, g.after);
  }
});

// Compile-time guard: the new reason codes exist in the union. If any is renamed
// or dropped this fails to type-check, keeping the catalog and engine in sync.
test("new reason codes are part of the ReasonCode union", () => {
  const codes: ReasonCode[] = [
    "BFLA_PRIVILEGED_FUNCTION",
    "BFLA_LOW_PRIV_ACTOR_2XX",
    "BFLA_ROLE_VERIFIED",
    "BFLA_ENFORCEMENT_OBSERVED",
    "MISSING_VERIFIED_ROLE",
    "MISSING_FUNCTION_PRIVILEGE_PROOF",
    "CSRF_STATE_CHANGE_COOKIE_AUTH",
    "CSRF_NO_TOKEN",
    "CSRF_SAMESITE_NONE",
    "CSRF_SAMESITE_DEFAULT_LAX",
    "REFRESH_TOKEN_REUSE",
    "REFRESH_TOKEN_REPLAYED",
    "REFRESH_ROTATION_OBSERVED",
    "SPEC_ENDPOINT_UNTESTED",
    "SPEC_SHADOW_ENDPOINT",
    "CAPTURE_TRUNCATED",
  ];
  assert.equal(new Set(codes).size, codes.length);
});
