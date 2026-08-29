#!/usr/bin/env node
/**
 * Full-desk Playwright flow: load lab capture → findings → playbook → forge → export redacts secrets.
 */
import { readFileSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chromium } from "playwright";

const url = process.env.E2E_URL || "http://127.0.0.1:8080/";
const timeout = Number(process.env.E2E_TIMEOUT_MS || 45000);

function fail(msg, extra) {
  console.error(JSON.stringify({ ok: false, error: msg, extra: extra ?? null }, null, 2));
  process.exit(1);
}

const browser = await chromium.launch({
  headless: true,
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});

try {
  const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
  page.setDefaultTimeout(timeout);
  const errors = [];
  page.on("pageerror", (err) => errors.push(String(err)));

  await page.goto(url, { waitUntil: "networkidle" });
  await page.getByRole("heading", { name: "ClaimForge" }).waitFor();
  await page.getByRole("button", { name: "Load lab capture" }).waitFor();

  for (const label of ["1 · Findings", "2 · Playbook", "3 · Forge"]) {
    if (!(await page.getByRole("tab", { name: label }).count())) fail(`missing primary tab ${label}`);
  }
  if (!(await page.getByLabel("More analysis views").count())) fail("missing More inspect select");

  await page.getByRole("button", { name: "Load lab capture" }).click();
  await page.locator("h3").filter({ hasText: /BOLA|IDOR/i }).first().waitFor({ timeout });
  const confirmed = await page.getByText("confirmed", { exact: false }).count();
  if (!confirmed) fail("expected a confirmed finding after lab capture");

  await page.getByRole("tab", { name: "2 · Playbook" }).click();
  await page.getByRole("heading", { name: /Horizontal access|Unsigned JWT|Replay pack/i }).first().waitFor({ timeout });

  await page.getByRole("tab", { name: "3 · Forge" }).click();
  const forgePanel = page.locator("#desk-panel");
  await forgePanel.getByText(/Mutate claims locally|No JWTs in the capture/i).first().waitFor({ timeout });
  if (await forgePanel.getByText("No JWTs in the capture to forge from.").count()) {
    fail("Forge had no JWTs after lab capture");
  }
  await forgePanel.getByRole("combobox").first().waitFor({ timeout });
  const minted = (await forgePanel.locator("pre").first().textContent()) ?? "";
  await page.getByRole("button", { name: "role admin" }).click();
  await page.waitForTimeout(200);
  const after = (await forgePanel.locator("pre").first().textContent()) ?? "";
  if (minted && after && minted === after && /[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/.test(minted)) {
    fail("Forge still showed the previous minted token after a claim edit", { minted, after });
  }

  const dlPath = join(tmpdir(), `claimforge-e2e-${Date.now()}.json`);
  const [download] = await Promise.all([
    page.waitForEvent("download", { timeout }),
    page.getByRole("button", { name: "Export JSON" }).click(),
  ]);
  await download.saveAs(dlPath);
  const json = readFileSync(dlPath, "utf8");
  try {
    unlinkSync(dlPath);
  } catch {
    /* tmp */
  }
  if (json.includes("dummysig") || json.includes("alice-session-01") || /"password"\s*:\s*"demo"/i.test(json)) {
    fail("export leaked token/cookie/password", { sample: json.slice(0, 400) });
  }
  if (!json.includes('"secrets": "redacted"') && !json.includes('"secrets":"redacted"')) {
    fail("export missing secrets:redacted marker");
  }

  const mobile = await browser.newPage({ viewport: { width: 390, height: 844 } });
  await mobile.goto(url, { waitUntil: "domcontentloaded" });
  await mobile.getByRole("heading", { name: "ClaimForge" }).waitFor();
  const findingsFirst = await mobile.getByRole("tab", { name: "1 · Findings" }).isVisible();
  if (!findingsFirst) fail("mobile missing Findings tab");

  if (errors.length) fail("page errors", errors);

  console.log(
    JSON.stringify({
      ok: true,
      url,
      confirmedFindings: confirmed,
      primaryTabs: 3,
      exportRedacted: true,
    }),
  );
} catch (e) {
  fail(e instanceof Error ? e.message : String(e));
} finally {
  await browser.close();
}
