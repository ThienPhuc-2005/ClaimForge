import { useState } from "react";
import { CopyBtn } from "@/components/copy-btn";
import { LAB_SECRET } from "@/lib/lab/constants";
import { useForge } from "@/lib/claimforge/store";

type Mode = "vulnerable" | "fixed";

interface HarEntry {
  startedDateTime: string;
  request: {
    method: string;
    url: string;
    headers: { name: string; value: string }[];
    postData?: { text: string };
  };
  response: {
    status: number;
    headers: { name: string; value: string }[];
    content: { text: string };
  };
}

function wrapHar(entries: HarEntry[]) {
  return JSON.stringify(
    { log: { version: "1.2", creator: { name: "ClaimForge victim lab", version: "1" }, entries } },
    null,
    2,
  );
}

function headerList(h: Headers): { name: string; value: string }[] {
  const out: { name: string; value: string }[] = [];
  h.forEach((value, name) => out.push({ name, value }));
  return out;
}

export function LabView() {
  const { setActor, setTab } = useForge();
  const [mode, setMode] = useState<Mode>("vulnerable");
  const [log, setLog] = useState<string[]>([]);
  const [entriesA, setEntriesA] = useState<HarEntry[]>([]);
  const [entriesB, setEntriesB] = useState<HarEntry[]>([]);
  const [busy, setBusy] = useState(false);

  async function call(path: string, init: RequestInit, actor: "A" | "B"): Promise<{ status: number; body: string }> {
    const url = `${window.location.origin}${path}`;
    const headers = new Headers(init.headers);
    headers.set("X-Lab-Mode", mode);
    const method = (init.method ?? "GET").toUpperCase();
    const res = await fetch(url, { ...init, method, headers });
    const body = await res.text();
    const startedDateTime = new Date().toISOString();
    const rec: HarEntry = {
      startedDateTime,
      request: {
        method,
        url,
        headers: headerList(headers),
        postData: init.body ? { text: String(init.body) } : undefined,
      },
      response: {
        status: res.status,
        headers: headerList(res.headers),
        content: { text: body },
      },
    };
    if (actor === "A") setEntriesA((e) => [...e, rec]);
    else setEntriesB((e) => [...e, rec]);
    setLog((l) => [`${actor} ${method} ${path} → ${res.status}`, ...l].slice(0, 24));
    return { status: res.status, body };
  }

  async function runBola() {
    setBusy(true);
    try {
      const aLogin = await call(
        "/api/lab/login",
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ email: "alice@lab.test", password: "demo" }),
        },
        "A",
      );
      const bLogin = await call(
        "/api/lab/login",
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ email: "bob@lab.test", password: "demo" }),
        },
        "B",
      );
      const aTok = (JSON.parse(aLogin.body) as { token: string }).token;
      const bTok = (JSON.parse(bLogin.body) as { token: string }).token;
      await call("/api/lab/invoices/5512", { headers: { Authorization: `Bearer ${aTok}` } }, "A");
      await call("/api/lab/invoices/5512", { headers: { Authorization: `Bearer ${bTok}` } }, "B");
    } finally {
      setBusy(false);
    }
  }

  async function runJwt() {
    setBusy(true);
    try {
      const forged = await call("/api/lab/forge-none", {}, "A");
      const token = (JSON.parse(forged.body) as { token: string }).token;
      await call("/api/lab/admin/users", { headers: { Authorization: `Bearer ${token}` } }, "A");
    } finally {
      setBusy(false);
    }
  }

  async function runLogout() {
    setBusy(true);
    try {
      const aLogin = await call(
        "/api/lab/login",
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ email: "alice@lab.test", password: "demo" }),
        },
        "A",
      );
      const tok = (JSON.parse(aLogin.body) as { token: string }).token;
      await call("/api/lab/me", { headers: { Authorization: `Bearer ${tok}` } }, "A");
      await call("/api/lab/logout", { method: "POST", headers: { Authorization: `Bearer ${tok}` } }, "A");
      await call("/api/lab/me", { headers: { Authorization: `Bearer ${tok}` } }, "A");
    } finally {
      setBusy(false);
    }
  }

  function loadIntoDesk() {
    if (entriesA.length) setActor("a", wrapHar(entriesA), true);
    if (entriesB.length) setActor("b", wrapHar(entriesB), true);
    setTab("findings");
  }

  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm leading-relaxed text-muted">
        Local victim API. Same routes, two implementations. Traffic stays in this browser until you import it into
        A/B.
      </p>
      <fieldset className="flex flex-col gap-2">
        <legend className="text-xs font-medium uppercase tracking-wide text-muted">Implementation</legend>
        <div className="flex flex-wrap gap-3">
          {(["vulnerable", "fixed"] as const).map((m) => (
            <label key={m} className="inline-flex min-h-11 items-center gap-2 text-sm">
              <input
                type="radio"
                name="lab-mode"
                checked={mode === m}
                onChange={() => setMode(m)}
                className="size-4 accent-accent"
              />
              {m === "vulnerable" ? "Vulnerable" : "Fixed"}
            </label>
          ))}
        </div>
        <p className="text-xs leading-relaxed text-muted">
          {mode === "vulnerable"
            ? "No object ACL, alg=none accepted, logout does not revoke the bearer."
            : "Owner check on invoices, HS256 only, logout denylists the token."}
        </p>
      </fieldset>
      <div className="flex flex-wrap gap-2" aria-busy={busy}>
        <LabBtn onClick={() => void runBola()} disabled={busy}>
          Run BOLA lab
        </LabBtn>
        <LabBtn onClick={() => void runJwt()} disabled={busy}>
          Run JWT lab
        </LabBtn>
        <LabBtn onClick={() => void runLogout()} disabled={busy}>
          Run logout lab
        </LabBtn>
        <LabBtn onClick={loadIntoDesk} disabled={!entriesA.length && !entriesB.length}>
          Import traffic into A/B
        </LabBtn>
      </div>
      <p className="text-xs text-muted">
        HMAC secret for Forge verify (lab tokens): <code className="font-mono">{LAB_SECRET}</code>
      </p>
      <CopyBtn text={LAB_SECRET} label="Copy lab HMAC" />
      <ol className="list-decimal space-y-1 pl-5 text-sm leading-relaxed text-muted">
        <li>BOLA — bob reads alice invoice 5512 (200 vs 403).</li>
        <li>JWT — alg=none admin token against /admin/users (200 vs 401).</li>
        <li>Logout — same bearer after POST /logout (200 vs 401).</li>
      </ol>
      <pre
        className="max-h-48 overflow-auto rounded-md border border-border bg-bg p-2 font-mono text-xs"
        aria-live="polite"
      >
        {log.join("\n") || "No lab calls yet."}
      </pre>
    </div>
  );
}

function LabBtn({
  children,
  onClick,
  disabled,
}: {
  children: string;
  onClick: () => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="min-h-11 rounded-md border border-border bg-elevated px-3 text-xs font-medium text-fg transition-colors duration-150 hover:border-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-50"
    >
      {children}
    </button>
  );
}
