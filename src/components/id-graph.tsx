import { useMemo, useState } from "react";
import { cn } from "@/lib/utils";
import { useForge } from "@/lib/claimforge/store";
import type { GraphNode } from "@/lib/claimforge/types";

const COL: Record<GraphNode["kind"], number> = { actor: 0, subject: 1, object: 2 };

export function IdGraph() {
  const { workspace } = useForge();
  const { nodes, edges } = workspace.graph;
  const [sel, setSel] = useState<string | null>(null);

  const laid = useMemo(() => {
    const cols: GraphNode[][] = [[], [], []];
    for (const n of nodes) cols[COL[n.kind]]!.push(n);
    const colW = 220;
    const rowH = 56;
    const padX = 36;
    const padY = 28;
    const pos = new Map<string, { x: number; y: number }>();
    let maxRows = 1;
    cols.forEach((col, ci) => {
      maxRows = Math.max(maxRows, col.length);
      col.forEach((n, ri) => {
        pos.set(n.id, { x: padX + ci * colW, y: padY + ri * rowH });
      });
    });
    return {
      pos,
      width: padX * 2 + colW * 2 + 120,
      height: padY * 2 + Math.max(maxRows - 1, 0) * rowH + 36,
    };
  }, [nodes]);

  const related = sel
    ? edges.filter((e) => e.from === sel || e.to === sel)
    : edges.filter((e) => e.bola);

  if (!nodes.length) {
    return <p className="p-6 text-sm text-muted">No identifiers to graph yet.</p>;
  }

  return (
    <div className="flex flex-col gap-3">
      <p className="text-xs text-muted">
        Subjects own objects. Red access edges are BOLA — the other actor read a foreign id and got 2xx.
        Click a node.
      </p>
      <div className="overflow-x-auto rounded-lg border border-border bg-bg">
        <svg
          role="img"
          aria-label="Object identifier graph"
          viewBox={`0 0 ${laid.width} ${laid.height}`}
          className="h-auto min-h-48 w-full min-w-[36rem]"
        >
          {edges.map((e, i) => {
            const a = laid.pos.get(e.from);
            const b = laid.pos.get(e.to);
            if (!a || !b) return null;
            const x1 = a.x + 88;
            const y1 = a.y + 16;
            const x2 = b.x;
            const y2 = b.y + 16;
            const mid = (x1 + x2) / 2;
            return (
              <path
                key={i}
                d={`M ${x1} ${y1} C ${mid} ${y1}, ${mid} ${y2}, ${x2} ${y2}`}
                fill="none"
                className={cn(e.bola ? "stroke-danger" : "stroke-border")}
                strokeWidth={e.bola ? 2 : 1.25}
                opacity={sel && e.from !== sel && e.to !== sel ? 0.25 : 1}
              />
            );
          })}
          {nodes.map((n) => {
            const p = laid.pos.get(n.id);
            if (!p) return null;
            const active = sel === n.id;
            return (
              <g
                key={n.id}
                transform={`translate(${p.x}, ${p.y})`}
                role="button"
                tabIndex={0}
                aria-label={n.label}
                className="cursor-pointer"
                onClick={() => setSel(n.id === sel ? null : n.id)}
                onKeyDown={(ev) => {
                  if (ev.key === "Enter" || ev.key === " ") {
                    ev.preventDefault();
                    setSel(n.id === sel ? null : n.id);
                  }
                }}
              >
                <rect
                  width="96"
                  height="32"
                  rx="6"
                  className={cn(
                    n.bola ? "stroke-danger fill-elevated" : "stroke-border fill-elevated",
                    active && "stroke-accent",
                  )}
                  strokeWidth={active || n.bola ? 1.75 : 1}
                />
                <text
                  x="48"
                  y="21"
                  textAnchor="middle"
                  className={cn(
                    "fill-fg font-mono",
                    n.kind === "actor" && "fill-accent",
                    n.bola && "fill-danger",
                  )}
                  fontSize="11"
                >
                  {n.label.slice(0, 12)}
                </text>
              </g>
            );
          })}
        </svg>
      </div>
      <ul className="space-y-1.5">
        {related.slice(0, 24).map((e, i) => (
          <li
            key={i}
            className={cn(
              "rounded-md border px-3 py-2 font-mono text-xs",
              e.bola ? "border-danger/40 text-danger" : "border-border text-muted",
            )}
          >
            {e.kind} · {e.actor ?? "—"} · {e.via}
            {e.status ? ` → ${e.status}` : ""}
          </li>
        ))}
        {!related.length && <li className="text-sm text-muted">No edges on this node.</li>}
      </ul>
    </div>
  );
}
