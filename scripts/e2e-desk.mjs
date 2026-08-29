#!/usr/bin/env node
/**
 * Full-desk Playwright: tabs, import, invalid capture, lab, more views,
 * persistence, keyboard, export redaction, screenshots.
 */
import { mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const url = process.env.E2E_URL || "http://127.0.0.1:8080/";
const timeout = Number(process.env.E2E_TIMEOUT_MS || 45000);
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SHOTS = join(ROOT, "docs/screenshots");

function fail(msg, extra) {
  console.error(JSON.stringify({ ok: false, error: msg, extra: extra ?? null }, null, 2));
  process.exit(1);
}

function step(name) {
  console.error("step", name);
}

async function selectedTab(page, id) {
  return page.locator(`#tab-${id}`).getAttribute("aria-selected");
}

async function waitSelected(page, id) {
  await page.waitForFunction(
    (tabId) =>
      document.getElementById(`tab-${tabId}`)?.getAttribute("aria-selected") === "true" &&
      document.activeElement?.id === `tab-${tabId}`,
    id,
    { timeout: 8000 },
  );
}

async function waitHydrated(page) {
  await page.waitForFunction(
    () => {
      const el = document.getElementById("tab-findings");
      if (!el) return false;
      return Object.keys(el).some(
        (k) => k.startsWith("__reactFiber") || k.startsWith("__reactProps") || k.startsWith("__reactInternalInstance"),
      );
    },
    null,
    { timeout },
  );
}

async function waitPersistFlag(page, on) {
  await page.waitForFunction(
    (want) => {
      try {
        const raw = localStorage.getItem("claimforge-v2");
        if (!raw) return want === false;
        const parsed = JSON.parse(raw);
        const flag = Boolean(parsed?.state?.persistCaptures);
        const hasRaw = Boolean(parsed?.state?.aRaw || parsed?.state?.bRaw);
        return want ? flag && hasRaw : !flag;
      } catch {
        return want === false;
      }
    },
    on,
    { timeout },
  );
}

const SAMPLE_HAR = JSON.stringify({
  log: {
    version: "1.2",
    entries: [
      {
        startedDateTime: "2026-08-29T10:00:00.000Z",
        request: {
          method: "GET",
          url: "https://shop.lab/api/invoices/5512",
          headers: [{ name: "Authorization", value: "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbGljZSJ9." }],
        },
        response: {
          status: 200,
          headers: [],
          content: { text: JSON.stringify({ id: 5512, ownerId: "alice" }) },
        },
      },
    ],
  },
});

const browser = await chromium.launch({
  headless: true,
  args: ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
});

try {
  const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
  page.setDefaultTimeout(timeout);
  const errors = [];
  page.on("pageerror", (err) => errors.push(String(err)));

  step("goto");
  await page.goto(url, { waitUntil: "domcontentloaded" });
  await page.getByRole("heading", { name: "ClaimForge" }).waitFor();
  await page.getByRole("button", { name: "Load lab capture" }).waitFor();
  await waitHydrated(page);

  step("screenshot onboarding");
  mkdirSync(SHOTS, { recursive: true });
  await page.screenshot({ path: join(SHOTS, "onboarding.png"), animations: "disabled" });

  for (const label of ["1 · Findings", "2 · Playbook", "3 · Forge"]) {
    if (!(await page.getByRole("tab", { name: label }).count())) fail(`missing primary tab ${label}`);
  }
  if (!(await page.getByLabel("More analysis views").count())) fail("missing More inspect select");

  step("tablist");
  const tablist = page.getByRole("tablist", { name: "Primary analysis views" });
  if ((await tablist.getByRole("tab").count()) !== 3) fail("tablist must contain only the three primary tabs");
  if (await tablist.locator("select").count()) fail("More select must not live inside tablist");

  step("keyboard");
  const findingsTab = page.getByRole("tab", { name: "1 · Findings" });
  await findingsTab.click();
  await findingsTab.focus();
  await page.keyboard.press("ArrowRight");
  await waitSelected(page, "playbook");

  await page.keyboard.press("ArrowRight");
  await waitSelected(page, "forge");
  await page.keyboard.press("ArrowRight");
  await waitSelected(page, "findings");

  await page.locator("#tab-findings").click();
  await page.locator("#tab-findings").focus();
  await page.keyboard.press("End");
  await waitSelected(page, "forge");
  await page.keyboard.press("Home");
  await waitSelected(page, "findings");

  step("more select does not steal tab arrows");
  await findingsTab.click();
  await page.getByLabel("More analysis views").focus();
  await page.keyboard.press("ArrowRight");
  if ((await selectedTab(page, "playbook")) === "true") {
    fail("ArrowRight on More select must not move primary tabs");
  }

  step("labelledby");
  await findingsTab.click();
  const labelledOk = await page.evaluate(() => {
    const panel = document.getElementById("desk-panel");
    const id = panel?.getAttribute("aria-labelledby");
    return panel?.getAttribute("role") === "tabpanel" && Boolean(id && document.getElementById(id));
  });
  if (!labelledOk) fail("tabpanel aria-labelledby points at a missing id");

  await page.getByLabel("More analysis views").selectOption("diff");
  const moreOk = await page.evaluate(() => {
    const panel = document.getElementById("desk-panel");
    const id = panel?.getAttribute("aria-labelledby");
    const orphan = Boolean(id && !document.getElementById(id));
    return (
      panel?.getAttribute("role") === "region" &&
      !orphan &&
      (panel?.getAttribute("aria-label") === "AuthZ diff" || panel?.getAttribute("aria-labelledby") === "more-views-select")
    );
  });
  if (!moreOk) fail("More view must be a labelled region, not a dangling tabpanel");
  await page.getByRole("table", { name: "Authorization diff by route" }).waitFor({ timeout });

  step("invalid json");
  await findingsTab.click();
  await page.getByLabel("Capture paste for actor A").fill("{not-json");
  await page.getByRole("alert").filter({ hasText: /incomplete or invalid/i }).waitFor({ timeout });

  step("file import");
  const harPath = join(tmpdir(), `claimforge-a-${Date.now()}.har`);
  writeFileSync(harPath, SAMPLE_HAR);
  await page.getByLabel(/Upload capture for actor A/).setInputFiles(harPath);
  try {
    unlinkSync(harPath);
  } catch {
    /* tmp */
  }
  await page.getByLabel("More analysis views").selectOption("traffic");
  await page.locator("#desk-panel").getByText(/\/api\/invoices\/5512/).waitFor({ timeout });

  step("load demo");
  await page.getByRole("tab", { name: "1 · Findings" }).click();
  await page.getByRole("button", { name: "Load lab capture" }).click();
  await page.locator("h3").filter({ hasText: /BOLA|IDOR/i }).first().waitFor({ timeout });
  const confirmed = await page.getByText("confirmed", { exact: false }).count();
  if (!confirmed) fail("expected a confirmed finding after lab capture");
  await page.screenshot({ path: join(SHOTS, "desk.png"), animations: "disabled" });

  step("playbook");
  await page.getByRole("tab", { name: "2 · Playbook" }).click();
  await page.getByRole("heading", { name: /Horizontal access|Unsigned JWT|Replay pack/i }).first().waitFor({ timeout });
  await page.screenshot({ path: join(SHOTS, "playbook.png"), animations: "disabled" });

  step("forge");
  await page.getByRole("tab", { name: "3 · Forge" }).click();
  const forgePanel = page.locator("#desk-panel");
  await forgePanel.getByText(/Mutate claims locally|No JWTs in the capture/i).first().waitFor({ timeout });
  if (await forgePanel.getByText("No JWTs in the capture to forge from.").count()) {
    fail("Forge had no JWTs after lab capture");
  }
  await forgePanel.getByRole("combobox").first().waitFor({ timeout });
  const minted = (await forgePanel.locator("pre").first().textContent()) ?? "";
  await page.getByRole("button", { name: "role admin" }).click();
  await forgePanel.locator("pre").first().waitFor();
  const after = (await forgePanel.locator("pre").first().textContent()) ?? "";
  if (minted && after && minted === after && /[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/.test(minted)) {
    fail("Forge still showed the previous minted token after a claim edit", { minted, after });
  }
  await page.screenshot({ path: join(SHOTS, "forge.png"), animations: "disabled" });

  step("more views");
  await page.getByLabel("More analysis views").selectOption("diff");
  await page.getByRole("table", { name: "Authorization diff by route" }).waitFor({ timeout });
  await page.getByLabel("More analysis views").selectOption("graph");
  await page.locator("#desk-panel svg").waitFor({ timeout });
  await page.screenshot({ path: join(SHOTS, "more.png"), animations: "disabled" });
  await page.getByLabel("More analysis views").selectOption("loot");
  await page.getByRole("heading", { name: "Harvest" }).waitFor({ timeout });
  await page.getByLabel("More analysis views").selectOption("timeline");
  await page.locator("#desk-panel").getByText(/Actor A/i).first().waitFor({ timeout });
  await page.getByLabel("More analysis views").selectOption("traffic");
  await page.getByRole("table").filter({ hasText: "Path" }).waitFor({ timeout });
  await page.getByLabel("More analysis views").selectOption("lab");
  await page.getByRole("button", { name: "Run BOLA lab" }).waitFor({ timeout });

  step("fixed lab bola");
  await page.getByRole("radio", { name: /Fixed/i }).check();
  await page.getByRole("button", { name: "Run BOLA lab" }).click();
  await page.locator("pre").filter({ hasText: /fixed B GET \/api\/lab\/invoices\/5512 → 403/ }).waitFor({ timeout });

  step("persist");
  await page.getByRole("tab", { name: "1 · Findings" }).click();
  await page.getByRole("checkbox", { name: /Keep HAR/i }).check();
  await waitPersistFlag(page, true);
  await page.reload({ waitUntil: "domcontentloaded" });
  await waitHydrated(page);
  await page.getByRole("tab", { name: "1 · Findings" }).click();
  await page.locator("h3").filter({ hasText: /BOLA|IDOR/i }).first().waitFor({ timeout });
  const persistOn = await page.getByRole("checkbox", { name: /Keep HAR/i }).isChecked();
  if (!persistOn) fail("persist checkbox should stay on after reload");

  await page.getByRole("checkbox", { name: /Keep HAR/i }).uncheck();
  await page.getByRole("button", { name: "Clear" }).click();
  await waitPersistFlag(page, false);
  await page.reload({ waitUntil: "domcontentloaded" });
  await waitHydrated(page);
  await page.getByRole("tab", { name: "1 · Findings" }).click();
  await page.getByRole("heading", { name: "Workflow" }).waitFor({ timeout });
  const persistOff = await page.getByRole("checkbox", { name: /Keep HAR/i }).isChecked();
  if (persistOff) fail("persist checkbox should stay off after reload");

  await page.getByRole("button", { name: "Load lab capture" }).click();
  await page.locator("h3").filter({ hasText: /BOLA|IDOR/i }).first().waitFor({ timeout });

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
  await waitHydrated(mobile);
  const findingsFirst = await mobile.getByRole("tab", { name: "1 · Findings" }).isVisible();
  if (!findingsFirst) fail("mobile missing Findings tab");
  await mobile.getByRole("button", { name: "Load lab capture" }).click();
  await mobile.locator("h3").filter({ hasText: /BOLA|IDOR/i }).first().waitFor({ timeout });
  await mobile.screenshot({ path: join(SHOTS, "mobile.png"), animations: "disabled" });

  if (errors.length) fail("page errors", errors);

  console.log(
    JSON.stringify({
      ok: true,
      url,
      confirmedFindings: confirmed,
      primaryTabs: 3,
      exportRedacted: true,
      screenshots: ["onboarding.png", "desk.png", "playbook.png", "forge.png", "more.png", "mobile.png"],
    }),
  );
} catch (e) {
  fail(e instanceof Error ? e.message : String(e));
} finally {
  await browser.close();
}
