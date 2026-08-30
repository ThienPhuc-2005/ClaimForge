import { useEffect, useMemo, useState } from "react";
import { CopyBtn } from "@/components/copy-btn";
import { mintJwt, signHs256, inspectJwt, verifyJwtWithKey } from "@/lib/claimforge/jwt.ts";
import { useForge } from "@/lib/claimforge/store";
import {
  applyDraft,
  canCopySignedAsValid,
  createForgeMachine,
  displayToken,
  FORGE_KIND_LABEL,
  markSigned,
  outputKind,
  snapshotFromDraft,
  type ForgeMachine,
} from "@/lib/claimforge/forge-revision.ts";
import { inspectJwksUrl } from "@/lib/claimforge/jwks-fetch.ts";
import { cn } from "@/lib/utils";

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
  const [verifyMsg, setVerifyMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [machine, setMachine] = useState<ForgeMachine>(() => createForgeMachine());
  const [jwksConfirmed, setJwksConfirmed] = useState(false);
  const [jwksPrompt, setJwksPrompt] = useState(false);

  function syncMachine(next: {
    header?: string;
    payload?: string;
    secret?: string;
    publicPem?: string;
    jwksUrl?: string;
    issuer?: string;
    audience?: string;
  }) {
    const h = next.header ?? header;
    const p = next.payload ?? payload;
    const s = next.secret ?? secret;
    const pem = next.publicPem ?? publicPem;
    const jwks = next.jwksUrl ?? jwksUrl;
    const iss = next.issuer ?? issuer;
    const aud = next.audience ?? audience;
    setMachine((m) =>
      applyDraft(
        m,
        snapshotFromDraft({
          header: h,
          payload: p,
          hmacSecret: s,
          publicPem: pem,
          jwksUrl: jwks,
          issuer: iss,
          audience: aud,
        }),
      ),
    );
  }

  useEffect(() => {
    if (!seed) return;
    const h = JSON.stringify(seed.header, null, 2);
    const p = JSON.stringify(seed.payload, null, 2);
    const iss = typeof seed.payload.iss === "string" ? seed.payload.iss : "";
    const aud =
      typeof seed.payload.aud === "string"
        ? seed.payload.aud
        : Array.isArray(seed.payload.aud)
          ? String(seed.payload.aud[0] ?? "")
          : "";
    setHeader(h);
    setPayload(p);
    setIssuer(iss);
    setAudience(aud);
    setVerifyMsg(null);
    setMachine(
      createForgeMachine(
        snapshotFromDraft({
          header: h,
          payload: p,
          hmacSecret: secret,
          publicPem,
          jwksUrl,
          issuer: iss,
          audience: aud,
        }),
      ),
    );
    // seed swap resets the machine; other fields stay as analyst-entered keys
    // eslint-disable-next-line react-hooks/exhaustive-deps
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
      const nh = JSON.stringify(h, null, 2);
      const np = JSON.stringify(p, null, 2);
      setHeader(nh);
      setPayload(np);
      syncMachine({ header: nh, payload: np });
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
      setMachine((m) => markSigned(m, token));
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
    if (jwksUrl && !jwksConfirmed) {
      const gate = inspectJwksUrl(jwksUrl);
      if (!gate.ok) {
        setVerifyMsg(gate.issues.join("; "));
        return;
      }
      setJwksPrompt(true);
      setVerifyMsg("Confirm JWKS fetch first — no request has been sent.");
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
        jwksConfirmed: jwksUrl ? jwksConfirmed : undefined,
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

  const kind = outputKind(machine);
  const out = minted.err ? "" : displayToken(machine, minted.token);
  const copySignedOk = canCopySignedAsValid(machine);

  return (
    <div className="flex flex-col gap-3">
      <p className="text-xs text-muted">
        Mutate claims locally. Verify HS* with a secret or RS256 with a PEM / JWKS. Bind iss and aud when you know them.
        Copy into a lab proxy — never spray from here. Changing header, payload, alg, keys, JWKS, iss, or aud voids a
        previous signature.
      </p>
      <p
        className={cn(
          "rounded-md border px-3 py-2 font-mono text-xs",
          kind === "signed-output" && "border-ok/40 text-ok",
          kind === "stale-output" && "border-danger/40 text-danger",
          kind === "unsigned-draft" && "border-border text-muted",
        )}
        role="status"
      >
        {FORGE_KIND_LABEL[kind]}
        {kind === "stale-output" ? " — signed compact JWT is not valid for copy. Use the unsigned draft or re-sign." : ""}
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
          onChange={(e) => {
            setSecret(e.target.value);
            syncMachine({ secret: e.target.value });
          }}
          className="mt-1 h-11 w-full rounded-md border border-border bg-bg px-3 font-mono text-sm text-fg outline-none ring-accent focus:ring-2"
        />
      </label>
      <label className="text-xs text-muted">
        RS256 public key (PEM)
        <textarea
          value={publicPem}
          onChange={(e) => {
            setPublicPem(e.target.value);
            syncMachine({ publicPem: e.target.value });
          }}
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
          onChange={(e) => {
            setJwksUrl(e.target.value);
            setJwksConfirmed(false);
            setJwksPrompt(false);
            syncMachine({ jwksUrl: e.target.value });
          }}
          placeholder="https://lab/.well-known/jwks.json"
          className="mt-1 h-11 w-full rounded-md border border-border bg-bg px-3 font-mono text-sm text-fg outline-none ring-accent focus:ring-2"
        />
      </label>
      {jwksPrompt &&
        (() => {
          const gate = inspectJwksUrl(jwksUrl);
          return (
            <div className="rounded-md border border-warn/40 bg-elevated p-3 text-xs" role="alertdialog" aria-label="Confirm JWKS fetch">
              <p className="font-medium text-fg">Confirm outbound JWKS request</p>
              <ul className="mt-2 space-y-1 text-muted">
                <li>Host: {gate.notice.hostname || "—"}</li>
                <li>Protocol: {gate.notice.protocol || "—"}</li>
                <li>Sends: {gate.notice.sends}</li>
                <li>Receives: {gate.notice.receives}</li>
              </ul>
              {!gate.ok && <p className="mt-2 text-danger">{gate.issues.join("; ")}</p>}
              <div className="mt-2 flex flex-wrap gap-2">
                <Preset
                  onClick={() => {
                    if (!gate.ok) return;
                    setJwksConfirmed(true);
                    setJwksPrompt(false);
                    setVerifyMsg("JWKS confirmed. Click Verify seed to fetch.");
                  }}
                >
                  Confirm fetch
                </Preset>
                <Preset
                  onClick={() => {
                    setJwksPrompt(false);
                    setJwksConfirmed(false);
                  }}
                >
                  Cancel
                </Preset>
              </div>
            </div>
          );
        })()}
      <div className="grid gap-3 md:grid-cols-2">
        <label className="text-xs text-muted">
          Expected issuer (iss)
          <input
            value={issuer}
            onChange={(e) => {
              setIssuer(e.target.value);
              syncMachine({ issuer: e.target.value });
            }}
            className="mt-1 h-11 w-full rounded-md border border-border bg-bg px-3 font-mono text-sm text-fg outline-none ring-accent focus:ring-2"
          />
        </label>
        <label className="text-xs text-muted">
          Expected audience (aud)
          <input
            value={audience}
            onChange={(e) => {
              setAudience(e.target.value);
              syncMachine({ audience: e.target.value });
            }}
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
              setHeader(e.target.value);
              syncMachine({ header: e.target.value });
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
              setPayload(e.target.value);
              syncMachine({ payload: e.target.value });
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
      <div className="flex flex-wrap gap-2">
        <CopyBtn text={minted.token} label="Copy unsigned draft" disabled={!minted.token} />
        <CopyBtn
          text={copySignedOk ? (machine.signedToken ?? "") : ""}
          label={copySignedOk ? "Copy signed JWT" : "Signed copy blocked (stale or unsigned)"}
          disabled={!copySignedOk}
        />
      </div>
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
