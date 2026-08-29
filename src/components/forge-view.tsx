import { useEffect, useMemo, useState } from "react";
import { CopyBtn } from "@/components/copy-btn";
import { mintJwt, signHs256, inspectJwt, verifyJwtWithKey } from "@/lib/claimforge/jwt.ts";
import { useForge } from "@/lib/claimforge/store";

export function ForgeView() {
  const { workspace, aLabel, bLabel } = useForge();
  const tokens = workspace.jwts;
  const [idx, setIdx] = useState(0);
  const seed = tokens[idx] ?? tokens[0];
  const [header, setHeader] = useState("{}");
  const [payload, setPayload] = useState("{}");
  const [secret, setSecret] = useState("");
  const [publicPem, setPublicPem] = useState("");
  const [jwksUrl, setJwksUrl] = useState("");
  const [issuer, setIssuer] = useState("");
  const [audience, setAudience] = useState("");
  const [signed, setSigned] = useState<string | null>(null);
  const [verifyMsg, setVerifyMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!seed) return;
    setHeader(JSON.stringify(seed.header, null, 2));
    setPayload(JSON.stringify(seed.payload, null, 2));
    setSigned(null);
    setVerifyMsg(null);
    setIssuer(typeof seed.payload.iss === "string" ? seed.payload.iss : "");
    setAudience(
      typeof seed.payload.aud === "string"
        ? seed.payload.aud
        : Array.isArray(seed.payload.aud)
          ? String(seed.payload.aud[0] ?? "")
          : "",
    );
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
      setSigned(null);
      setHeader(JSON.stringify(h, null, 2));
      setPayload(JSON.stringify(p, null, 2));
    } catch {
      /* invalid JSON — minted.err already surfaces */
    }
  }

  async function sign() {
    setBusy(true);
    try {
      const h = JSON.parse(header) as Record<string, unknown>;
      const p = JSON.parse(payload) as Record<string, unknown>;
      if (!secret) {
        setVerifyMsg("Need an HMAC secret to sign HS256.");
        return;
      }
      const token = await signHs256(p, secret, h);
      setSigned(token);
      setVerifyMsg("Signed with jose HS256.");
    } catch (e) {
      setVerifyMsg(e instanceof Error ? e.message : "sign failed");
    } finally {
      setBusy(false);
    }
  }

  async function verifySeed() {
    if (!seed) return;
    if (!secret && !publicPem && !jwksUrl) {
      setVerifyMsg("Need an HMAC secret, RS256 public key (PEM), or JWKS URL.");
      return;
    }
    setBusy(true);
    try {
      const ins = inspectJwt(seed.raw, seed.actor, seed.source);
      if (!ins) {
        setVerifyMsg("Could not parse seed.");
        return;
      }
      const v = await verifyJwtWithKey(ins, {
        secret: secret || undefined,
        publicKeyPem: publicPem || undefined,
        jwksUrl: jwksUrl || undefined,
        issuer: issuer || undefined,
        audience: audience || undefined,
      });
      setVerifyMsg(v.sigStatus === "verified" ? "Signature valid (jose)." : `Result: ${v.sigStatus}. ${v.issues.at(-1) ?? ""}`);
    } finally {
      setBusy(false);
    }
  }

  if (!tokens.length) {
    return <p className="p-6 text-sm text-muted">No JWTs in the capture to forge from.</p>;
  }

  const out = signed && !minted.err ? signed : minted.token;

  return (
    <div className="flex flex-col gap-3">
      <p className="text-xs text-muted">
        Mutate claims locally. Verify HS* with a secret or RS256 with a PEM / JWKS. Bind iss and aud when you know them.
        Copy into a lab proxy — never spray from here.
      </p>
      <label className="text-xs text-muted">
        Seed
        <select
          className="mt-1 h-11 w-full rounded-md border border-border bg-elevated px-2 text-sm text-fg"
          value={idx}
          onChange={(e) => setIdx(Number(e.target.value))}
          aria-label="JWT seed"
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
      <label className="text-xs text-muted">
        HMAC secret (jose HS256)
        <input
          type="password"
          autoComplete="off"
          value={secret}
          onChange={(e) => setSecret(e.target.value)}
          className="mt-1 h-11 w-full rounded-md border border-border bg-bg px-3 font-mono text-sm text-fg outline-none ring-accent focus:ring-2"
        />
      </label>
      <label className="text-xs text-muted">
        RS256 public key (PEM)
        <textarea
          value={publicPem}
          onChange={(e) => setPublicPem(e.target.value)}
          spellCheck={false}
          aria-label="RS256 public key PEM"
          placeholder="-----BEGIN PUBLIC KEY-----"
          className="mt-1 h-24 w-full rounded-md border border-border bg-bg p-2 font-mono text-xs text-fg outline-none ring-accent focus:ring-2"
        />
      </label>
      <label className="text-xs text-muted">
        JWKS URL
        <input
          type="url"
          value={jwksUrl}
          onChange={(e) => setJwksUrl(e.target.value)}
          placeholder="https://lab/.well-known/jwks.json"
          className="mt-1 h-11 w-full rounded-md border border-border bg-bg px-3 font-mono text-sm text-fg outline-none ring-accent focus:ring-2"
        />
      </label>
      <div className="grid gap-3 md:grid-cols-2">
        <label className="text-xs text-muted">
          Expected issuer (iss)
          <input
            value={issuer}
            onChange={(e) => setIssuer(e.target.value)}
            className="mt-1 h-11 w-full rounded-md border border-border bg-bg px-3 font-mono text-sm text-fg outline-none ring-accent focus:ring-2"
          />
        </label>
        <label className="text-xs text-muted">
          Expected audience (aud)
          <input
            value={audience}
            onChange={(e) => setAudience(e.target.value)}
            className="mt-1 h-11 w-full rounded-md border border-border bg-bg px-3 font-mono text-sm text-fg outline-none ring-accent focus:ring-2"
          />
        </label>
      </div>
      <div className="flex flex-wrap gap-2">
        <Preset onClick={() => void sign()}>{busy ? "Working…" : "Sign HS256"}</Preset>
        <Preset onClick={() => void verifySeed()}>Verify seed</Preset>
      </div>
      {verifyMsg && <p className="text-xs text-muted">{verifyMsg}</p>}
      <div className="grid gap-3 md:grid-cols-2">
        <label className="text-xs text-muted">
          Header
          <textarea
            value={header}
            onChange={(e) => {
              setSigned(null);
              setHeader(e.target.value);
            }}
            spellCheck={false}
            className="mt-1 h-36 w-full rounded-md border border-border bg-bg p-2 font-mono text-xs text-fg outline-none ring-accent focus:ring-2"
          />
        </label>
        <label className="text-xs text-muted">
          Payload
          <textarea
            value={payload}
            onChange={(e) => {
              setSigned(null);
              setPayload(e.target.value);
            }}
            spellCheck={false}
            className="mt-1 h-36 w-full rounded-md border border-border bg-bg p-2 font-mono text-xs text-fg outline-none ring-accent focus:ring-2"
          />
        </label>
      </div>
      {minted.err && <p className="text-xs text-danger">{minted.err}</p>}
      <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-md border border-border bg-bg p-2 font-mono text-xs">
        {out || "—"}
      </pre>
      <CopyBtn text={out} label="Copy minted JWT" />
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
