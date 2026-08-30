import { CopyBtn } from "@/components/copy-btn";
import { useForge } from "@/lib/claimforge/store";
import { cn } from "@/lib/utils";

export function PlaybookView() {
  const { workspace } = useForge();
  return (
    <div className="flex flex-col gap-5">
      <p className="text-xs leading-relaxed text-muted">
        Kill chain from this capture. Curls are for your interceptor / authorized lab — this app never fires them.
        Replay wipes source credentials, then attaches only the selected actor set. Values below are masked.
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
              {r.credentialSource && (
                <p className="mt-2 font-mono text-[11px] text-muted">
                  Credential source: actor {r.credentialSource.actor}
                  {r.credentialSource.kinds.length ? ` · ${r.credentialSource.kinds.join(", ")}` : ""}
                </p>
              )}
              {r.headerDiff && r.headerDiff.length > 0 && (
                <div className="mt-2 overflow-x-auto">
                  <table className="w-full text-left font-mono text-[11px]">
                    <caption className="sr-only">Credential header diff (masked)</caption>
                    <thead>
                      <tr className="text-muted">
                        <th className="py-1 pr-3 font-medium">Header</th>
                        <th className="py-1 pr-3 font-medium">Before</th>
                        <th className="py-1 font-medium">After</th>
                      </tr>
                    </thead>
                    <tbody>
                      {r.headerDiff.map((d) => (
                        <tr key={d.name} className="border-t border-border">
                          <td className="py-1 pr-3">{d.name}</td>
                          <td className="py-1 pr-3 text-muted">{d.before}</td>
                          <td className="py-1">{d.after}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              <details className="mt-2">
                <summary className="cursor-pointer text-xs text-muted">Show curl (contains selected actor secrets)</summary>
                <pre className="mt-2 overflow-x-auto whitespace-pre-wrap font-mono text-xs text-fg">{r.curl}</pre>
              </details>
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
