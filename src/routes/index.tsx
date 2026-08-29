import { createFileRoute } from "@tanstack/react-router";
import {
  Download,
  Eraser,
  FlaskConical,
  KeyRound,
  ShieldAlert,
  Upload,
} from "lucide-react";
import { useMemo, useRef, type ReactNode } from "react";
import { cn } from "@/lib/utils";
import { useForge } from "@/lib/claimforge/store";
import { IdGraph } from "@/components/id-graph";
import { PlaybookView } from "@/components/playbook-view";
import { ForgeView } from "@/components/forge-view";
import { LootView } from "@/components/loot-view";
import { engagementMarkdown } from "@/lib/claimforge/report.ts";
import type { Finding, Severity } from "@/lib/claimforge/types";

export const Route = createFileRoute("/")({ component: Home });

const TABS = [
  { id: "findings", label: "Findings" },
  { id: "playbook", label: "Playbook" },
  { id: "forge", label: "Forge" },
  { id: "diff", label: "AuthZ diff" },
  { id: "graph", label: "ID graph" },
  { id: "loot", label: "Loot" },
  { id: "timeline", label: "Timeline" },
  { id: "traffic", label: "Traffic" },
] as const;

function Home() {
  const {
    aLabel,
    bLabel,
    aRaw,
    bRaw,
    tab,
    workspace,
    setActor,
    setLabel,
    setTab,
    loadDemo,
    clearAll,
  } = useForge();
  const crit = workspace.findings.filter((f) => f.severity === "critical").length;
  const high = workspace.findings.filter((f) => f.severity === "high").length;

  function exportReport() {
    const blob = new Blob(
      [
        JSON.stringify(
          {
            generated: new Date().toISOString(),
            tool: "ClaimForge",
            actors: { A: aLabel, B: bLabel },
            findings: workspace.findings,
            diffs: workspace.diffs,
            timeline: workspace.timeline,
            jwts: workspace.jwts.map((j) => ({
              actor: j.actor,
              alg: j.alg,
              issues: j.issues,
              payload: j.payload,
            })),
            cookies: workspace.cookies,
            graph: workspace.graph,
            loot: workspace.loot,
            paths: workspace.paths,
            replays: workspace.replays,
          },
          null,
          2,
        ),
      ],
      { type: "application/json" },
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "claimforge-report.json";
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="min-h-dvh bg-bg text-fg">
      <header className="border-b border-border px-4 py-3 md:px-6">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <KeyRound className="size-5 text-accent" strokeWidth={1.75} />
            <div>
              <p className="text-sm font-semibold tracking-tight">ClaimForge</p>
              <p className="text-xs text-muted">Red team auth desk · offline</p>
            </div>
          </div>
          <div className="ml-auto flex flex-wrap gap-2">
            <GhostBtn onClick={loadDemo} icon={<FlaskConical className="size-4" />}>
              Load lab capture
            </GhostBtn>
            <GhostBtn onClick={exportReport} icon={<Download className="size-4" />}>
              Export JSON
            </GhostBtn>
            <GhostBtn
              onClick={() => {
                const blob = new Blob([engagementMarkdown(workspace)], { type: "text/markdown" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                a.download = "claimforge-engagement.md";
                a.click();
                URL.revokeObjectURL(url);
              }}
              icon={<Download className="size-4" />}
            >
              Export MD
            </GhostBtn>
            <GhostBtn onClick={clearAll} icon={<Eraser className="size-4" />}>
              Clear
            </GhostBtn>
          </div>
        </div>
        <dl className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
          <Stat k="Requests" v={String(workspace.requests.length)} />
          <Stat k="Critical" v={String(crit)} hot={crit > 0} />
          <Stat k="High" v={String(high)} hot={high > 0} />
          <Stat k="Loot" v={String(workspace.loot.length)} hot={workspace.loot.length > 0} />
        </dl>
      </header>

      <div className="grid gap-4 p-4 lg:grid-cols-[minmax(0,18rem)_1fr] md:p-6">
        <aside className="flex flex-col gap-3">
          <ImportCard
            actor="A"
            label={aLabel}
            raw={aRaw}
            onLabel={(v) => setLabel("a", v)}
            onRaw={(v) => setActor("a", v)}
          />
          <ImportCard
            actor="B"
            label={bLabel}
            raw={bRaw}
            onLabel={(v) => setLabel("b", v)}
            onRaw={(v) => setActor("b", v)}
          />
          <p className="text-xs leading-relaxed text-muted">
            Drop HAR or Burp XML for two roles. Playbook curls stay in this browser until you paste them into a lab interceptor.
          </p>
        </aside>

        <section className="min-w-0 rounded-xl border border-border bg-surface p-3 md:p-4">
          <div className="flex gap-1 overflow-x-auto pb-3">
            {TABS.map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => setTab(t.id)}
                className={cn(
                  "shrink-0 rounded-md px-3 py-2 text-sm font-medium transition-colors duration-150",
                  tab === t.id ? "bg-accent text-accent-fg" : "text-muted hover:bg-elevated hover:text-fg",
                )}
              >
                {t.label}
              </button>
            ))}
          </div>
          {tab === "findings" && <FindingsList findings={workspace.findings} />}
          {tab === "playbook" && <PlaybookView />}
          {tab === "forge" && <ForgeView />}
          {tab === "diff" && <DiffTable />}
          {tab === "graph" && <IdGraph />}
          {tab === "loot" && <LootView />}
          {tab === "timeline" && <Timeline />}
          {tab === "traffic" && <Traffic />}
        </section>
      </div>
    </div>
  );
}

function GhostBtn({
  children,
  onClick,
  icon,
}: {
  children: ReactNode;
  onClick: () => void;
  icon: ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="inline-flex min-h-11 items-center gap-2 rounded-md border border-border bg-elevated px-3 text-sm font-medium text-fg transition-colors duration-150 hover:border-accent"
    >
      {icon}
      {children}
    </button>
  );
}

function Stat({ k, v, hot }: { k: string; v: string; hot?: boolean }) {
  return (
    <div className="rounded-lg border border-border bg-surface px-3 py-2">
      <dt className="text-xs text-muted">{k}</dt>
      <dd className={cn("tabular text-lg font-semibold", hot && "text-danger")}>{v}</dd>
    </div>
  );
}

function ImportCard({
  actor,
  label,
  raw,
  onLabel,
  onRaw,
}: {
  actor: "A" | "B";
  label: string;
  raw: string;
  onLabel: (v: string) => void;
  onRaw: (v: string) => void;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  return (
    <div className="rounded-xl border border-border bg-surface p-3">
      <div className="mb-2 flex items-center justify-between gap-2">
        <span className="text-xs font-medium uppercase tracking-wide text-muted">Actor {actor}</span>
        <button
          type="button"
          className="inline-flex min-h-11 items-center gap-1 rounded-md px-2 text-xs text-muted hover:text-fg"
          onClick={() => inputRef.current?.click()}
        >
          <Upload className="size-3.5" /> File
        </button>
        <input
          ref={inputRef}
          type="file"
          accept=".har,.json,.txt,.xml,application/json,text/xml,application/xml"
          className="hidden"
          onChange={async (e) => {
            const f = e.target.files?.[0];
            if (!f) return;
            onRaw(await f.text());
            e.target.value = "";
          }}
        />
      </div>
      <input
        value={label}
        onChange={(e) => onLabel(e.target.value)}
        aria-label={`Actor ${actor} name`}
        className="mb-2 h-11 w-full rounded-md border border-border bg-elevated px-3 text-sm text-fg outline-none ring-accent focus:ring-2"
      />
      <textarea
        value={raw}
        onChange={(e) => onRaw(e.target.value)}
        spellCheck={false}
        placeholder="HAR, Burp XML, raw HTTP, or JWT"
        className="h-36 w-full resize-y rounded-md border border-border bg-bg p-2 font-mono text-xs text-fg outline-none ring-accent focus:ring-2"
      />
    </div>
  );
}

function sevClass(s: Severity) {
  if (s === "critical" || s === "high") return "text-danger border-danger/40";
  if (s === "medium") return "text-warn border-warn/40";
  if (s === "low") return "text-ok border-ok/40";
  return "text-muted border-border";
}

function FindingsList({ findings }: { findings: Finding[] }) {
  if (!findings.length) {
    return <p className="p-6 text-sm text-muted">Import two captures to score auth bugs.</p>;
  }
  return (
    <ul className="flex flex-col gap-2">
      {findings.map((f) => (
        <li key={f.id} className="rounded-lg border border-border bg-elevated p-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className={cn("rounded-sm border px-1.5 py-0.5 font-mono text-[11px] uppercase", sevClass(f.severity))}>
              {f.severity}
            </span>
            <h2 className="text-sm font-medium">{f.title}</h2>
          </div>
          <p className="mt-2 text-sm text-muted">{f.why}</p>
          <ul className="mt-2 space-y-1 font-mono text-xs text-subtle">
            {f.evidence.filter(Boolean).map((e) => (
              <li key={e} className="truncate">
                {e}
              </li>
            ))}
          </ul>
          <p className="mt-2 text-xs leading-relaxed text-fg">{f.how}</p>
        </li>
      ))}
    </ul>
  );
}

function DiffTable() {
  const { workspace, aLabel, bLabel } = useForge();
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[36rem] text-left text-sm">
        <thead className="text-xs uppercase text-muted">
          <tr>
            <th className="py-2 pr-3 font-medium">Route</th>
            <th className="py-2 pr-3 font-medium">{aLabel} A</th>
            <th className="py-2 pr-3 font-medium">{bLabel} B</th>
            <th className="py-2 font-medium">Verdict</th>
          </tr>
        </thead>
        <tbody>
          {workspace.diffs.map((row) => (
            <tr key={row.method + row.template} className="border-t border-border align-top">
              <td className="py-2 pr-3 font-mono text-xs">
                {row.method} {row.template}
              </td>
              <td className="tabular py-2 pr-3 text-xs">{row.aStatuses.join(", ") || "—"}</td>
              <td className="tabular py-2 pr-3 text-xs">{row.bStatuses.join(", ") || "—"}</td>
              <td className="py-2 text-xs">
                <span className={cn(row.verdict === "bola" && "font-medium text-danger")}>{row.note}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {!workspace.diffs.length && <p className="p-6 text-sm text-muted">No overlapping routes yet.</p>}
    </div>
  );
}

function Timeline() {
  const { workspace } = useForge();
  const items = useMemo(
    () => [...workspace.timeline].sort((a, b) => a.at - b.at),
    [workspace.timeline],
  );
  return (
    <ol className="relative space-y-3 border-l border-border pl-4">
      {items.map((ev, i) => (
        <li key={ev.requestId ?? i} className="relative">
          <span className="absolute -left-[1.15rem] top-1 size-2 rounded-full bg-accent" />
          <p className="text-xs text-muted">
            Actor {ev.actor} · {ev.kind} ·{" "}
            <span className="tabular">{new Date(ev.at).toISOString().slice(11, 19)}</span>
          </p>
          <p className="text-sm">{ev.label}</p>
          <p className="font-mono text-xs text-subtle">{ev.detail}</p>
        </li>
      ))}
      {!items.length && <p className="text-sm text-muted">No timestamped events.</p>}
    </ol>
  );
}

function Traffic() {
  const { workspace } = useForge();
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[40rem] text-left text-xs">
        <thead className="text-muted">
          <tr>
            <th className="py-2 pr-2 font-medium">Actor</th>
            <th className="py-2 pr-2 font-medium">Status</th>
            <th className="py-2 pr-2 font-medium">Method</th>
            <th className="py-2 font-medium">Path</th>
          </tr>
        </thead>
        <tbody>
          {workspace.requests.map((r) => (
            <tr key={r.id} className="border-t border-border">
              <td className="py-1.5 pr-2">{r.actor}</td>
              <td className={cn("tabular py-1.5 pr-2", r.status === 200 && "text-ok", r.status >= 400 && "text-danger")}>
                {r.status || "—"}
              </td>
              <td className="py-1.5 pr-2 font-mono">{r.method}</td>
              <td className="max-w-xs truncate py-1.5 font-mono" title={r.url}>
                {r.path}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {!workspace.requests.length && (
        <div className="flex items-start gap-2 p-6 text-sm text-muted">
          <ShieldAlert className="mt-0.5 size-4 shrink-0" />
          Paste captures on the left.
        </div>
      )}
    </div>
  );
}
