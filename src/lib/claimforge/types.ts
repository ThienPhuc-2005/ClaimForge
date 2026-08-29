export type ActorId = "A" | "B";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface HttpHeader {
  name: string;
  value: string;
}

export interface CapturedRequest {
  id: string;
  actor: ActorId;
  startedAt: number;
  method: string;
  url: string;
  origin: string;
  path: string;
  template: string;
  query: Record<string, string>;
  requestHeaders: HttpHeader[];
  requestBody?: string;
  status: number;
  statusText: string;
  responseHeaders: HttpHeader[];
  responseBody?: string;
  timeMs: number;
}

export interface JwtToken {
  actor: ActorId;
  raw: string;
  source: string;
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  alg?: string;
  parts: number;
  issues: string[];
}

export interface CookieRecord {
  actor: ActorId;
  name: string;
  value: string;
  source: "request" | "set-cookie";
  flags: {
    httpOnly: boolean;
    secure: boolean;
    sameSite: string | null;
    path?: string;
    domain?: string;
    maxAge?: string;
    expires?: string;
  };
  issues: string[];
}

export interface TimelineEvent {
  at: number;
  actor: ActorId;
  kind: "login" | "refresh" | "logout" | "authz" | "error" | "traffic";
  label: string;
  detail: string;
  requestId?: string;
}

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  why: string;
  evidence: string[];
  template?: string;
  how: string;
}

export interface DiffRow {
  template: string;
  method: string;
  aStatuses: number[];
  bStatuses: number[];
  aSample?: CapturedRequest;
  bSample?: CapturedRequest;
  verdict: "bola" | "denied" | "same" | "a-only" | "b-only" | "mixed";
  note: string;
}

export interface Workspace {
  aLabel: string;
  bLabel: string;
  aRaw: string;
  bRaw: string;
  requests: CapturedRequest[];
  jwts: JwtToken[];
  cookies: CookieRecord[];
  timeline: TimelineEvent[];
  diffs: DiffRow[];
  findings: Finding[];
  idsA: string[];
  idsB: string[];
  graph: { nodes: GraphNode[]; edges: GraphEdge[] };
  loot: LootItem[];
  wordlists: Wordlists;
  surface: SurfaceRow[];
  paths: AttackPath[];
  replays: ReplayItem[];
}

export interface LootItem {
  kind: "secret" | "key" | "stack" | "cors" | "mass-assign" | "internal";
  severity: Severity;
  label: string;
  value: string;
  where: string;
  actor: ActorId;
}

export interface Wordlists {
  ids: string[];
  emails: string[];
  roles: string[];
  hosts: string[];
}

export interface SurfaceRow {
  method: string;
  template: string;
  hosts: string[];
  statuses: number[];
  actors: ActorId[];
  auth: boolean;
  interesting: string[];
}

export interface AttackPath {
  id: string;
  title: string;
  objective: string;
  steps: string[];
  findingIds: string[];
}

export interface ReplayItem {
  id: string;
  title: string;
  severity: Severity;
  note: string;
  curl: string;
  raw: string;
}

export type GraphNodeKind = "actor" | "subject" | "object";

export interface GraphNode {
  id: string;
  kind: GraphNodeKind;
  label: string;
  owners: ActorId[];
  seenBy: ActorId[];
  bola: boolean;
}

export interface GraphEdge {
  from: string;
  to: string;
  kind: "session" | "owns" | "access";
  actor?: ActorId;
  via: string;
  status?: number;
  bola: boolean;
}
