import { CopyBtn } from "@/components/copy-btn";
import { useForge } from "@/lib/claimforge/store";
import { cn } from "@/lib/utils";

export function PlaybookView() {
  const { workspace } = useForge();
  return (
    <div className="flex flex-col gap-5">
      <p className="text-xs leading-relaxed text-muted">
        Kill chain from this capture. Curls are for your interceptor / authorized lab — this app never fires them.
      </p>
      <ol className="flex flex-col gap-3">
        {workspace.paths.map((p, i) => (
          <li key={p.id} className="rounded-lg border border-border bg-elevated p-3">
            <p className="text-xs text-muted">Path {i + 1}</p>
            <h2 className="text-sm font-medium">{p.title}</h2>
            <p className="mt-1 text-sm text-muted">{p.objective}</p>
            <ol className="mt-2 list-decimal space-y-1 pl-4 text-sm">
              {p.steps.map((s) => (
                <li key={s}>{s}</li>
              ))}
            </ol>
          </li>
        ))}
      </ol>
      <div>
        <h2 className="mb-2 text-sm font-medium">Replay pack</h2>
        <ul className="flex flex-col gap-2">
          {workspace.replays.map((r) => (
            <li key={r.id} className="rounded-lg border border-border bg-bg p-3">
              <div className="flex flex-wrap items-center gap-2">
                <span
                  className={cn(
                    "rounded-sm border px-1.5 py-0.5 font-mono text-[11px] uppercase",
                    r.severity === "critical" || r.severity === "high"
                      ? "border-danger/40 text-danger"
                      : "border-border text-muted",
                  )}
                >
                  {r.severity}
                </span>
                <h3 className="text-sm font-medium">{r.title}</h3>
              </div>
              <p className="mt-1 text-xs text-muted">{r.note}</p>
              <pre className="mt-2 overflow-x-auto whitespace-pre-wrap font-mono text-xs text-fg">{r.curl}</pre>
              <div className="mt-2 flex flex-wrap gap-2">
                <CopyBtn text={r.curl} label="Copy curl" />
                <CopyBtn text={r.raw} label="Copy raw HTTP" />
              </div>
            </li>
          ))}
          {!workspace.replays.length && (
            <li className="text-sm text-muted">No replay recipes yet — import two roles with overlapping object ids.</li>
          )}
        </ul>
      </div>
    </div>
  );
}
