import { useEffect, useMemo, useState } from "react";
import { CopyBtn } from "@/components/copy-btn";
import { mintJwt } from "@/lib/claimforge/jwt.ts";
import { useForge } from "@/lib/claimforge/store";

export function ForgeView() {
  const { workspace, aLabel, bLabel } = useForge();
  const tokens = workspace.jwts;
  const [idx, setIdx] = useState(0);
  const seed = tokens[idx] ?? tokens[0];
  const [header, setHeader] = useState("{}");
  const [payload, setPayload] = useState("{}");

  useEffect(() => {
    if (!seed) return;
    setHeader(JSON.stringify(seed.header, null, 2));
    setPayload(JSON.stringify(seed.payload, null, 2));
  }, [seed]);

  const minted = useMemo(() => {
    try {
      const h = JSON.parse(header) as Record<string, unknown>;
      const p = JSON.parse(payload) as Record<string, unknown>;
      return { token: mintJwt(h, p), err: null as string | null };
    } catch (e) {
      return { token: "", err: e instanceof Error ? e.message : "invalid JSON" };
    }
  }, [header, payload]);

  function apply(mut: (h: Record<string, unknown>, p: Record<string, unknown>) => void) {
    try {
      const h = JSON.parse(header) as Record<string, unknown>;
      const p = JSON.parse(payload) as Record<string, unknown>;
      mut(h, p);
      setHeader(JSON.stringify(h, null, 2));
      setPayload(JSON.stringify(p, null, 2));
    } catch {
      /* invalid JSON — minted.err already surfaces */
    }
  }

  if (!tokens.length) {
    return <p className="p-6 text-sm text-muted">No JWTs in the capture to forge from.</p>;
  }

  return (
    <div className="flex flex-col gap-3">
      <p className="text-xs text-muted">
        Mutate claims locally. Copy the token into Burp Repeater on a lab — never spray it from here.
      </p>
      <label className="text-xs text-muted">
        Seed
        <select
          className="mt-1 h-11 w-full rounded-md border border-border bg-elevated px-2 text-sm text-fg"
          value={idx}
          onChange={(e) => setIdx(Number(e.target.value))}
        >
          {tokens.map((t, i) => (
            <option key={i} value={i}>
              {t.actor} · {t.alg ?? "?"} · {t.sigStatus} · {t.source}
            </option>
          ))}
        </select>
      </label>
      <div className="flex flex-wrap gap-2">
        <Preset
          onClick={() =>
            apply((h) => {
              h.alg = "none";
              delete h.jwk;
            })
          }
        >
          alg none
        </Preset>
        <Preset
          onClick={() =>
            apply((_, p) => {
              p.role = "admin";
              p.is_admin = true;
            })
          }
        >
          role admin
        </Preset>
        <Preset
          onClick={() =>
            apply((_, p) => {
              p.sub = p.sub === aLabel ? bLabel : aLabel;
            })
          }
        >
          swap sub
        </Preset>
        <Preset
          onClick={() =>
            apply((_, p) => {
              p.exp = 9999999999;
            })
          }
        >
          exp far
        </Preset>
      </div>
      <div className="grid gap-3 md:grid-cols-2">
        <label className="text-xs text-muted">
          Header
          <textarea
            value={header}
            onChange={(e) => setHeader(e.target.value)}
            spellCheck={false}
            className="mt-1 h-36 w-full rounded-md border border-border bg-bg p-2 font-mono text-xs text-fg outline-none ring-accent focus:ring-2"
          />
        </label>
        <label className="text-xs text-muted">
          Payload
          <textarea
            value={payload}
            onChange={(e) => setPayload(e.target.value)}
            spellCheck={false}
            className="mt-1 h-36 w-full rounded-md border border-border bg-bg p-2 font-mono text-xs text-fg outline-none ring-accent focus:ring-2"
          />
        </label>
      </div>
      {minted.err && <p className="text-xs text-danger">{minted.err}</p>}
      <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-md border border-border bg-bg p-2 font-mono text-xs">
        {minted.token || "—"}
      </pre>
      <CopyBtn text={minted.token} label="Copy minted JWT" />
    </div>
  );
}

function Preset({ children, onClick }: { children: string; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="min-h-11 rounded-md border border-border bg-elevated px-3 text-xs font-medium text-fg hover:border-accent"
    >
      {children}
    </button>
  );
}
