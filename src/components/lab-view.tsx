import { useMemo, useState, type ReactNode } from "react";
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

type Bucket = { a: HarEntry[]; b: HarEntry[]; log: string[] };

const emptyBucket = (): Bucket => ({ a: [], b: [], log: [] });

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
  const [buckets, setBuckets] = useState<Record<Mode, Bucket>>({
    vulnerable: emptyBucket(),
    fixed: emptyBucket(),
  });
  const [busy, setBusy] = useState(false);
  const bucket = buckets[mode];

  const mixedHint = useMemo(() => {
    const other: Mode = mode === "vulnerable" ? "fixed" : "vulnerable";
    const o = buckets[other];
    if ((o.a.length || o.b.length) && (bucket.a.length || bucket.b.length)) {
      return `Other mode (${other}) has ${o.a.length + o.b.length} calls kept separately — import uses ${mode} only.`;
    }
    return null;
  }, [buckets, mode, bucket.a.length, bucket.b.length]);

  function pushEntry(actor: "A" | "B", rec: HarEntry, line: string) {
    setBuckets((prev) => {
      const cur = prev[mode];
      const next: Bucket = {
        a: actor === "A" ? [...cur.a, rec] : cur.a,
        b: actor === "B" ? [...cur.b, rec] : cur.b,
        log: [line, ...cur.log].slice(0, 24),
      };
      return { ...prev, [mode]: next };
    });
  }

  async function call(path: string, init: RequestInit, actor: "A" | "B"): Promise<{ status: number; body: string }> {
    const url = `${window.location.origin}${path}`;
    const headers = new Headers(init.headers);
    headers.set("X-Lab-Mode", mode);
    const method = (init.method ?? "GET").toUpperCase();
    const res = await fetch(url, { ...init, method, headers });
    const body = await res.text();
    const rec: HarEntry = {
      startedDateTime: new Date().toISOString(),
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
    pushEntry(actor, rec, `${mode} ${actor} ${method} ${path} → ${res.status}`);
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
    const a = buckets[mode].a;
    const b = buckets[mode].b;
    if (a.length) setActor("a", wrapHar(a), true);
    if (b.length) setActor("b", wrapHar(b), true);
    setTab("findings");
  }

  function clearMode() {
    setBuckets((prev) => ({ ...prev, [mode]: emptyBucket() }));
  }

  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm leading-relaxed text-muted">
        Local victim API. Same routes, two implementations. Vulnerable and Fixed traffic are stored separately so
        mixed-mode captures cannot pollute findings.
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
              <span className="text-xs text-subtle">
                ({buckets[m].a.length + buckets[m].b.length} calls)
              </span>
            </label>
          ))}
        </div>
        <p className="text-xs leading-relaxed text-muted">
          {mode === "vulnerable"
            ? "No object ACL, alg=none accepted, logout does not revoke the bearer."
            : "Owner check on invoices, HS256 only, logout denylists the token."}
        </p>
        {mixedHint && <p className="text-xs text-warn">{mixedHint}</p>}
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
        <LabBtn onClick={loadIntoDesk} disabled={!bucket.a.length && !bucket.b.length}>
          Import {mode} into A/B
        </LabBtn>
        <LabBtn onClick={clearMode} disabled={!bucket.a.length && !bucket.b.length}>
          Clear {mode} bucket
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
        {bucket.log.join("\n") || `No ${mode} lab calls yet.`}
      </pre>
    </div>
  );
}

function LabBtn({
  children,
  onClick,
  disabled,
}: {
  children: ReactNode;
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
