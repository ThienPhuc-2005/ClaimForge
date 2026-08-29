import type { ActorId, CapturedRequest, GraphEdge, GraphNode, JwtToken } from "./types.ts";
import { jwtSubject } from "./jwt.ts";
import { ownerLinks, pathIds } from "./ids.ts";

function nodeKey(kind: GraphNode["kind"], value: string) {
  return `${kind}:${value}`;
}

export function buildIdGraph(
  requests: CapturedRequest[],
  jwts: JwtToken[],
  aLabel: string,
  bLabel: string,
): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const nodes = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];
  const seenEdge = new Set<string>();

  const upsert = (kind: GraphNode["kind"], value: string, extra?: Partial<GraphNode>) => {
    const id = nodeKey(kind, value);
    const prev = nodes.get(id);
    if (prev) {
      if (extra?.owners) prev.owners = [...new Set([...prev.owners, ...extra.owners])];
      if (extra?.seenBy) prev.seenBy = [...new Set([...prev.seenBy, ...extra.seenBy])];
      if (extra?.bola) prev.bola = true;
      return prev;
    }
    const n: GraphNode = {
      id,
      kind,
      label: value,
      owners: extra?.owners ?? [],
      seenBy: extra?.seenBy ?? [],
      bola: extra?.bola ?? false,
    };
    nodes.set(id, n);
    return n;
  };

  const link = (e: GraphEdge) => {
    const k = `${e.from}|${e.to}|${e.kind}|${e.actor ?? ""}|${e.via}`;
    if (seenEdge.has(k)) return;
    seenEdge.add(k);
    edges.push(e);
  };

  upsert("actor", "A", { owners: ["A"], seenBy: ["A"] }).label = aLabel || "A";
  upsert("actor", "B", { owners: ["B"], seenBy: ["B"] }).label = bLabel || "B";

  const subjectOf: Record<ActorId, string | null> = { A: null, B: null };
  for (const j of jwts) {
    const sub = jwtSubject(j);
    if (!sub) continue;
    if (!subjectOf[j.actor]) subjectOf[j.actor] = sub;
    upsert("subject", sub, { owners: [j.actor], seenBy: [j.actor] });
    link({
      from: nodeKey("actor", j.actor),
      to: nodeKey("subject", sub),
      kind: "session",
      actor: j.actor,
      via: `JWT ${j.source}`,
      bola: false,
    });
  }

  for (const req of requests) {
    if (req.method === "PASTE") continue;
    const actorNode = nodeKey("actor", req.actor);
    const sub = subjectOf[req.actor];
    const ok = req.status >= 200 && req.status < 300;

    for (const rel of [...ownerLinks(req.responseBody), ...ownerLinks(req.requestBody)]) {
      upsert("subject", rel.owner, { seenBy: [req.actor] });
      upsert("object", rel.object, { owners: sub === rel.owner ? [req.actor] : [], seenBy: [req.actor] });
      const obj = nodes.get(nodeKey("object", rel.object))!;
      if (subjectOf.A === rel.owner) obj.owners = [...new Set([...obj.owners, "A" as ActorId])];
      if (subjectOf.B === rel.owner) obj.owners = [...new Set([...obj.owners, "B" as ActorId])];
      link({
        from: nodeKey("subject", rel.owner),
        to: nodeKey("object", rel.object),
        kind: "owns",
        actor: req.actor,
        via: `${req.method} ${req.path}`,
        status: req.status,
        bola: false,
      });
    }

    for (const pid of pathIds(req.path)) {
      const obj = upsert("object", pid, { seenBy: [req.actor] });
      const foreign = obj.owners.length > 0 && !obj.owners.includes(req.actor);
      const bola = Boolean(foreign && ok);
      if (bola) obj.bola = true;
      const from = sub ? nodeKey("subject", sub) : actorNode;
      link({
        from,
        to: obj.id,
        kind: "access",
        actor: req.actor,
        via: `${req.method} ${req.path}`,
        status: req.status,
        bola,
      });
    }
  }

  // If an object was never given owners via JSON but only A touched it in-path, mark A as owner
  for (const n of nodes.values()) {
    if (n.kind !== "object") continue;
    if (n.owners.length) continue;
    const accessors = [...new Set(edges.filter((e) => e.to === n.id && e.kind === "access").map((e) => e.actor).filter(Boolean))] as ActorId[];
    if (accessors.length === 1) n.owners = accessors;
  }

  for (const e of edges) {
    if (e.kind !== "access") continue;
    const obj = nodes.get(e.to);
    if (!obj || !e.actor) continue;
    if (obj.owners.length && !obj.owners.includes(e.actor) && e.status && e.status >= 200 && e.status < 300) {
      e.bola = true;
      obj.bola = true;
    }
  }

  const used = new Set<string>();
  for (const e of edges) {
    used.add(e.from);
    used.add(e.to);
  }
  const list = [...nodes.values()].filter((n) => used.has(n.id) || n.kind === "actor");
  return { nodes: list, edges };
}
