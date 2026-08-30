import { createFileRoute } from "@tanstack/react-router";
import {
  Download,
  Eraser,
  FlaskConical,
  KeyRound,
  ShieldAlert,
  Upload,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { cn } from "@/lib/utils";
import { useForge } from "@/lib/claimforge/store";
import { IdGraph } from "@/components/id-graph";
import { PlaybookView } from "@/components/playbook-view";
import { ForgeView } from "@/components/forge-view";
import { LootView } from "@/components/loot-view";
import { LabView } from "@/components/lab-view";
import { PolicyView } from "@/components/policy-view";
import { engagementMarkdown, renderReportJson, toReportDTO } from "@/lib/claimforge/report.ts";
import { MAX_CAPTURE_BYTES } from "@/lib/claimforge/limits.ts";
import {
  deskPanelLabelledBy,
  deskPanelRole,
  isDeskNavKey,
  isPrimaryTab,
  nextPrimaryTab,
} from "@/lib/claimforge/desk-nav.ts";
import type { Finding, FindingConfidence, ReviewState, Severity } from "@/lib/claimforge/types";
import {
  canTransitionReview,
  CONFIDENCE_CLASSES,
  REVIEW_STATES,
  reviewLabel,
} from "@/lib/claimforge/review.ts";

export const Route = createFileRoute("/")({ component: Home });

const PRIMARY_TABS = [
  { id: "findings", label: "1 · Findings" },
  { id: "playbook", label: "2 · Playbook" },
  { id: "forge", label: "3 · Forge" },
] as const;

const MORE_TABS = [
  { id: "diff", label: "AuthZ diff" },
  { id: "graph", label: "ID graph" },
  { id: "loot", label: "Loot" },
  { id: "timeline", label: "Timeline" },
  { id: "traffic", label: "Traffic" },
  { id: "lab", label: "Victim lab" },
  { id: "policy", label: "Policy" },
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
    persistCaptures,
    setPersistCaptures,
    analyzing,
    importError,
    parseErrorA,
    parseErrorB,
  } = useForge();
  const crit = workspace.findings.filter((f) => f.severity === "critical").length;
  const high = workspace.findings.filter((f) => f.severity === "high").length;

  function exportReport() {
    const blob = new Blob([renderReportJson(toReportDTO(workspace))], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "claimforge-report.json";
    a.click();
    URL.revokeObjectURL(url);
  }

  function onTabKey(e: KeyboardEvent<HTMLElement>) {
    if (!isDeskNavKey(e.key)) return;
    const target = e.target as HTMLElement | null;
    if (target?.closest("select, textarea, input")) return;
    e.preventDefault();
    const focusedId = target?.id?.startsWith("tab-") ? target.id.slice(4) : "";
    const id = nextPrimaryTab(focusedId, tab, e.key);
    setTab(id);
    requestAnimationFrame(() => document.getElementById(`tab-${id}`)?.focus());
  }

  const primarySelected = isPrimaryTab(tab);
  const moreLabel = MORE_TABS.find((t) => t.id === tab)?.label;
  const labelledBy = deskPanelLabelledBy(tab);
  const panelName = moreLabel ?? PRIMARY_TABS.find((t) => t.id === tab)?.label ?? "Analysis";

  return (
    <div className="min-h-dvh bg-bg text-fg">
      <a
        href="#desk"
        className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded-md focus:bg-accent focus:px-3 focus:py-2 focus:text-accent-fg"
      >
        Skip to analysis
      </a>
      <header className="border-b border-border px-4 py-3 md:px-6">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <KeyRound className="size-5 text-accent" strokeWidth={1.75} aria-hidden />
            <div>
              <h1 className="text-sm font-semibold tracking-tight">ClaimForge</h1>
              <p className="text-xs text-muted">Red team auth desk · client-side processing</p>
            </div>
          </div>
          <div className="ml-auto flex flex-wrap gap-2">
            <GhostBtn onClick={loadDemo} icon={<FlaskConical className="size-4" aria-hidden />}>
              Load lab capture
            </GhostBtn>
            <GhostBtn onClick={exportReport} icon={<Download className="size-4" aria-hidden />}>
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
              icon={<Download className="size-4" aria-hidden />}
            >
              Export MD
            </GhostBtn>
            <GhostBtn onClick={clearAll} icon={<Eraser className="size-4" aria-hidden />}>
              Clear
            </GhostBtn>
          </div>
        </div>
        <label className="mt-3 inline-flex min-h-11 items-center gap-2 text-xs text-muted">
          <input
            type="checkbox"
            checked={persistCaptures}
            onChange={(e) => setPersistCaptures(e.target.checked)}
            className="size-4 accent-accent"
          />
          Keep HAR / JWT / cookies in this browser (off by default)
        </label>
        {analyzing && (
          <p className="mt-2 text-xs text-muted" role="status" aria-live="polite">
            Analyzing capture…
          </p>
        )}
        {importError && (
          <p className="mt-2 text-xs text-danger" role="alert">
            {importError}
          </p>
        )}
        <dl className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
          <Stat k="Requests" v={String(workspace.requests.length)} />
          <Stat k="Critical" v={String(crit)} hot={crit > 0} />
          <Stat k="High" v={String(high)} hot={high > 0} />
          <Stat k="Loot" v={String(workspace.loot.length)} hot={workspace.loot.length > 0} />
        </dl>
      </header>

      <main className="grid gap-4 p-4 lg:grid-cols-[minmax(0,18rem)_1fr] md:p-6">
        <section
          id="desk"
          className="order-1 min-w-0 rounded-xl border border-border bg-surface p-3 md:p-4 lg:order-2 lg:col-start-2 lg:row-start-1"
        >
          <div className="flex flex-wrap items-end gap-2 overflow-x-auto pb-3">
            <div
              className="flex gap-1"
              role="tablist"
              aria-label="Primary analysis views"
              aria-orientation="horizontal"
              onKeyDown={onTabKey}
            >
            {PRIMARY_TABS.map((t) => (
              <button
                key={t.id}
                id={`tab-${t.id}`}
                type="button"
                role="tab"
                aria-selected={tab === t.id}
                aria-controls={primarySelected ? "desk-panel" : undefined}
                tabIndex={tab === t.id || (!primarySelected && t.id === "findings") ? 0 : -1}
                onClick={() => setTab(t.id)}
                onKeyDown={onTabKey}
                className={cn(
                  "shrink-0 rounded-md px-3 py-2 text-sm font-medium transition-colors duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent",
                  tab === t.id ? "bg-accent text-accent-fg" : "text-muted hover:bg-elevated hover:text-fg",
                )}
              >
                {t.label}
              </button>
            ))}
            </div>
            <label className="ml-auto shrink-0 text-xs text-muted">
              More
              <select
                id="more-views-select"
                className="ml-2 h-11 rounded-md border border-border bg-elevated px-2 text-sm text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                aria-label="More analysis views"
                value={MORE_TABS.some((t) => t.id === tab) ? tab : ""}
                onChange={(e) => {
                  const id = e.target.value as (typeof MORE_TABS)[number]["id"];
                  if (id) setTab(id);
                }}
              >
                <option value="">Inspect…</option>
                {MORE_TABS.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.label}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <div
            id="desk-panel"
            role={deskPanelRole(tab)}
            aria-labelledby={labelledBy}
            aria-label={labelledBy ? undefined : panelName}
          >
            {!workspace.requests.length && tab !== "lab" && tab !== "policy" ? (
              <Onboarding onDemo={loadDemo} onLab={() => setTab("lab")} />
            ) : null}
            {tab === "findings" && workspace.requests.length > 0 && <FindingsList findings={workspace.findings} />}
            {tab === "playbook" && <PlaybookView />}
            {tab === "forge" && <ForgeView />}
            {tab === "diff" && <DiffTable />}
            {tab === "graph" && <IdGraph />}
            {tab === "loot" && <LootView />}
            {tab === "timeline" && <Timeline />}
            {tab === "traffic" && <Traffic />}
            {tab === "lab" && <LabView />}
            {tab === "policy" && <PolicyView />}
          </div>
        </section>

        <aside
          className="order-2 flex flex-col gap-3 lg:order-1 lg:col-start-1 lg:row-start-1"
          aria-label="Actor captures"
        >
          <ImportCard
            actor="A"
            label={aLabel}
            raw={aRaw}
            parseError={parseErrorA}
            onLabel={(v) => setLabel("a", v)}
            onRaw={(v, immediate) => setActor("a", v, immediate)}
          />
          <ImportCard
            actor="B"
            label={bLabel}
            raw={bRaw}
            parseError={parseErrorB}
            onLabel={(v) => setLabel("b", v)}
            onRaw={(v, immediate) => setActor("b", v, immediate)}
          />
          <p className="text-xs leading-relaxed text-muted">
            Drop HAR or Burp XML for two roles. Analysis is client-side in this browser (a hosted shell may still load
            platform scripts). Captures are not saved unless you opt in. Export redacts JWT, cookie, and bearer values.
          </p>
        </aside>
      </main>
    </div>
  );
}

function Onboarding({ onDemo, onLab }: { onDemo: () => void; onLab: () => void }) {
  return (
    <div className="flex flex-col gap-3 p-4 md:p-6">
      <h2 className="text-base font-semibold">Workflow</h2>
      <ol className="list-decimal space-y-2 pl-5 text-sm leading-relaxed text-muted">
        <li>Capture — paste two HARs (or Victim lab, one implementation at a time).</li>
        <li>Findings — Observation / Suspicion / Confirmed. Confirmed BOLA needs ownerId or inventory, not an unverified JWT sub.</li>
        <li>Playbook — copy curl into your interceptor. This desk never fires it. Exports redact tokens, cookies, and passwords.</li>
      </ol>
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          onClick={onDemo}
          className="min-h-11 rounded-md bg-accent px-4 text-sm font-medium text-accent-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          Load sample capture
        </button>
        <button
          type="button"
          onClick={onLab}
          className="min-h-11 rounded-md border border-border bg-elevated px-4 text-sm font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          Open victim lab
        </button>
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
      className="inline-flex min-h-11 items-center gap-2 rounded-md border border-border bg-elevated px-3 text-sm font-medium text-fg transition-colors duration-150 hover:border-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
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
  parseError,
  onLabel,
  onRaw,
}: {
  actor: "A" | "B";
  label: string;
  raw: string;
  parseError: string | null;
  onLabel: (v: string) => void;
  onRaw: (v: string, immediate?: boolean) => void;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const setImportError = useForge((s) => s.setImportError);
  const mb = Math.round(MAX_CAPTURE_BYTES / (1024 * 1024));
  const [open, setOpen] = useState(false);
  useEffect(() => {
    const mq = window.matchMedia("(min-width: 1024px)");
    const apply = () => setOpen(mq.matches);
    apply();
    mq.addEventListener("change", apply);
    return () => mq.removeEventListener("change", apply);
  }, []);
  return (
    <details
      className="rounded-xl border border-border bg-surface p-3"
      open={open}
      onToggle={(e) => setOpen((e.target as HTMLDetailsElement).open)}
    >
      <summary className="flex min-h-11 cursor-pointer list-none items-center justify-between gap-2 text-sm font-medium text-fg">
        <span>
          Actor {actor}
          <span className="ml-2 text-xs font-normal text-muted">{label || "unnamed"}</span>
        </span>
        <span className="text-xs text-subtle">{raw ? `${Math.round(raw.length / 1024)} KB` : "empty"}</span>
      </summary>
      <div className="mt-2">
        <div className="mb-2 flex items-center justify-end gap-2">
          <button
            type="button"
            className="inline-flex min-h-11 items-center gap-1 rounded-md px-2 text-xs text-muted hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            onClick={() => inputRef.current?.click()}
            aria-label={`Upload capture file for actor ${actor}`}
          >
            <Upload className="size-3.5" aria-hidden /> File
          </button>
          <input
            ref={inputRef}
            type="file"
            accept=".har,.json,.txt,.xml,application/json,text/xml,application/xml"
            className="hidden"
            aria-label={`Upload capture for actor ${actor}, maximum ${mb} megabytes`}
            onChange={async (e) => {
              const f = e.target.files?.[0];
              if (!f) return;
              if (f.size > MAX_CAPTURE_BYTES) {
                setImportError(`Capture exceeds ${mb} MB limit.`);
                e.target.value = "";
                return;
              }
              onRaw(await f.text(), true);
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
          aria-invalid={Boolean(parseError)}
          aria-describedby={parseError ? `parse-err-${actor}` : undefined}
          aria-label={`Capture paste for actor ${actor}`}
          placeholder="HAR, Burp XML, raw HTTP, or JWT"
          className="h-28 w-full resize-y rounded-md border border-border bg-bg p-2 font-mono text-xs text-fg outline-none ring-accent focus:ring-2 md:h-36"
        />
        {parseError ? (
          <p id={`parse-err-${actor}`} className="mt-1 text-xs text-danger" role="alert">
            {parseError}
          </p>
        ) : (
          <p className="mt-1 text-xs text-subtle">Max {mb} MB · paste is debounced</p>
        )}
      </div>
    </details>
  );
}

function sevClass(s: Severity) {
  if (s === "critical" || s === "high") return "text-danger border-danger/40";
  if (s === "medium") return "text-warn border-warn/40";
  if (s === "low") return "text-ok border-ok/40";
  return "text-muted border-border";
}

function FindingsList({ findings }: { findings: Finding[] }) {
  const setFindingReview = useForge((s) => s.setFindingReview);
  const [confFilter, setConfFilter] = useState<"all" | FindingConfidence>("all");
  const [reviewFilter, setReviewFilter] = useState<"all" | ReviewState>("all");
  const visible = findings.filter(
    (f) => (confFilter === "all" || f.confidence === confFilter) && (reviewFilter === "all" || f.reviewState === reviewFilter),
  );
  if (!findings.length) {
    return <p className="p-6 text-sm text-muted">Import two captures to score auth bugs.</p>;
  }
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-end gap-3">
        <label className="text-xs text-muted">
          Confidence
          <select
            className="ml-2 h-9 rounded-md border border-border bg-elevated px-2 text-sm text-fg"
            value={confFilter}
            onChange={(e) => setConfFilter(e.target.value as "all" | FindingConfidence)}
            aria-label="Filter by confidence"
          >
            <option value="all">All</option>
            {CONFIDENCE_CLASSES.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        </label>
        <label className="text-xs text-muted">
          Review
          <select
            className="ml-2 h-9 rounded-md border border-border bg-elevated px-2 text-sm text-fg"
            value={reviewFilter}
            onChange={(e) => setReviewFilter(e.target.value as "all" | ReviewState)}
            aria-label="Filter by review state"
          >
            <option value="all">All</option>
            {REVIEW_STATES.map((s) => (
              <option key={s} value={s}>
                {reviewLabel(s)}
              </option>
            ))}
          </select>
        </label>
        <p className="text-xs text-subtle">
          {visible.length}/{findings.length} · engine confidence is separate from analyst review
        </p>
      </div>
      <ul className="flex flex-col gap-2">
        {visible.map((f) => (
          <li key={f.id} className="rounded-lg border border-border bg-elevated p-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className={cn("rounded-sm border px-1.5 py-0.5 font-mono text-[11px] uppercase", sevClass(f.severity))}>
                {f.severity}
              </span>
              <span className="rounded-sm border border-border px-1.5 py-0.5 font-mono text-[11px] uppercase text-muted">
                {f.confidence}
              </span>
              <h3 className="text-sm font-medium">{f.title}</h3>
              <label className="ml-auto text-xs text-muted">
                Review
                <select
                  className="ml-2 h-9 rounded-md border border-border bg-bg px-2 text-xs text-fg"
                  value={f.reviewState}
                  aria-label={`Review state for ${f.title}`}
                  onChange={(e) => {
                    const to = e.target.value as ReviewState;
                    if (!setFindingReview(f.fingerprint || f.id, to)) {
                      e.target.value = f.reviewState;
                    }
                  }}
                >
                  {REVIEW_STATES.map((s) => (
                    <option key={s} value={s} disabled={!canTransitionReview(f.reviewState, s)}>
                      {reviewLabel(s)}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <p className="mt-2 text-sm leading-relaxed text-muted">{f.why}</p>
            <p className="mt-2 font-mono text-[11px] text-subtle">{f.reasonCodes.join(" · ")}</p>
            {f.missingEvidence?.length ? (
              <p className="mt-1 text-xs text-warn">Missing: {f.missingEvidence.join("; ")}</p>
            ) : null}
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
    </div>
  );
}

function DiffTable() {
  const { workspace, aLabel, bLabel } = useForge();
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[36rem] text-left text-sm">
        <caption className="sr-only">Authorization diff by route</caption>
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
                <span
                  className={cn(
                    row.verdict === "bola" && "font-medium text-danger",
                    row.verdict === "suspect" && "text-warn",
                    row.verdict === "shared" && "text-muted",
                  )}
                >
                  {row.note}
                </span>
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
        <caption className="sr-only">Captured HTTP traffic</caption>
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
