export type ForgeOutputKind = "unsigned-draft" | "signed-output" | "stale-output";

export interface ForgeRevisionSnapshot {
  header: string;
  payload: string;
  alg: string;
  hmacSecret: string;
  publicPem: string;
  jwksUrl: string;
  kid: string;
  issuer: string;
  audience: string;
}

export interface ForgeMachine {
  revision: number;
  signedAtRevision: number | null;
  signedToken: string | null;
  snapshot: ForgeRevisionSnapshot;
}

export function emptySnapshot(): ForgeRevisionSnapshot {
  return {
    header: "{}",
    payload: "{}",
    alg: "",
    hmacSecret: "",
    publicPem: "",
    jwksUrl: "",
    kid: "",
    issuer: "",
    audience: "",
  };
}

export function snapshotFromDraft(input: {
  header: string;
  payload: string;
  hmacSecret?: string;
  publicPem?: string;
  jwksUrl?: string;
  issuer?: string;
  audience?: string;
}): ForgeRevisionSnapshot {
  let alg = "";
  let kid = "";
  try {
    const h = JSON.parse(input.header) as Record<string, unknown>;
    if (typeof h.alg === "string") alg = h.alg;
    if (typeof h.kid === "string") kid = h.kid;
  } catch {
    /* keep empty */
  }
  return {
    header: input.header,
    payload: input.payload,
    alg,
    hmacSecret: input.hmacSecret ?? "",
    publicPem: input.publicPem ?? "",
    jwksUrl: input.jwksUrl ?? "",
    kid,
    issuer: input.issuer ?? "",
    audience: input.audience ?? "",
  };
}

export function snapshotsEqual(a: ForgeRevisionSnapshot, b: ForgeRevisionSnapshot): boolean {
  return (
    a.header === b.header &&
    a.payload === b.payload &&
    a.alg === b.alg &&
    a.hmacSecret === b.hmacSecret &&
    a.publicPem === b.publicPem &&
    a.jwksUrl === b.jwksUrl &&
    a.kid === b.kid &&
    a.issuer === b.issuer &&
    a.audience === b.audience
  );
}

export function createForgeMachine(snapshot: ForgeRevisionSnapshot = emptySnapshot()): ForgeMachine {
  return { revision: 1, signedAtRevision: null, signedToken: null, snapshot };
}

/** If the draft diverges, bump revision and void the signed token as stale (kept for display only). */
export function applyDraft(machine: ForgeMachine, next: ForgeRevisionSnapshot): ForgeMachine {
  if (snapshotsEqual(machine.snapshot, next)) return machine;
  return {
    ...machine,
    revision: machine.revision + 1,
    snapshot: next,
  };
}

export function markSigned(machine: ForgeMachine, token: string): ForgeMachine {
  if (!token) return machine;
  return {
    ...machine,
    signedToken: token,
    signedAtRevision: machine.revision,
  };
}

export function outputKind(machine: ForgeMachine): ForgeOutputKind {
  if (machine.signedToken && machine.signedAtRevision === machine.revision) return "signed-output";
  if (machine.signedToken && machine.signedAtRevision !== machine.revision) return "stale-output";
  return "unsigned-draft";
}

export function displayToken(machine: ForgeMachine, unsignedDraft: string): string {
  const kind = outputKind(machine);
  if (kind === "signed-output") return machine.signedToken ?? unsignedDraft;
  return unsignedDraft;
}

/** Signed compact JWT is only copyable as valid when the machine is signed-output. */
export function canCopySignedAsValid(machine: ForgeMachine): boolean {
  return outputKind(machine) === "signed-output";
}

export const FORGE_KIND_LABEL: Record<ForgeOutputKind, string> = {
  "unsigned-draft": "Unsigned draft",
  "signed-output": "Signed output",
  "stale-output": "Stale output",
};
