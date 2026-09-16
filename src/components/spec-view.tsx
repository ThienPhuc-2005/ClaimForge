import { CopyBtn } from "@/components/copy-btn";
import { useForge } from "@/lib/claimforge/store";
import { cn } from "@/lib/utils";

export function SpecView() {
  const { workspace } = useForge();
  const cov = workspace.specCoverage;

  if (!cov) {
    return (
      <div className="flex flex-col gap-3 p-4 md:p-6">
        <h2 className="text-base font-semibold">API spec coverage</h2>
        <p className="text-sm leading-relaxed text-muted">
          Paste an OpenAPI 3 or Swagger 2 <span className="font-mono">JSON</span> spec in the sidebar (API spec card).
          ClaimForge diffs the declared surface against the captured traffic — it never sends a request. You&apos;ll see
          which declared endpoints were never exercised (blind spots) and which live routes are undocumented (shadow API).
        </p>
      </div>
    );
  }

  if (cov.error) {
    return (
      <div className="flex flex-col gap-3 p-4 md:p-6">
        <h2 className="text-base font-semibold">API spec coverage</h2>
        <p className="rounded-md border border-danger/40 bg-danger/10 px-3 py-2 text-sm text-danger" role="alert">
          {cov.error}
        </p>
      </div>
    );
  }

  const pct = cov.declaredCount ? Math.round((cov.coveredCount / cov.declaredCount) * 100) : 0;
  const untestedList = cov.untested.map((o) => `${o.method} ${o.path}`).join("\n");
  const shadowList = cov.shadow.map((s) => `${s.method} ${s.template}`).join("\n");

  return (
    <div className="flex flex-col gap-5">
      <div>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-sm font-medium">
            Coverage · <span className="text-muted">{cov.source}</span>
            {cov.title ? <span className="ml-1 text-muted">· {cov.title}</span> : null}
          </h2>
          <span className="tabular text-sm font-semibold">
            {cov.coveredCount}/{cov.declaredCount} exercised ({pct}%)
          </span>
        </div>
        <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-elevated" aria-hidden>
          <div
            className={cn("h-full rounded-full", pct >= 66 ? "bg-ok" : pct >= 33 ? "bg-warn" : "bg-danger")}
            style={{ width: `${pct}%` }}
          />
        </div>
        <p className="mt-2 text-xs text-subtle">
          Coverage counts an endpoint as exercised only when a non-error (&lt;400) response was seen. Untested secured /
          write endpoints are blind spots, not proof of a bug.
        </p>
      </div>

      <div>
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-sm font-medium">
            Untested endpoints <span className="text-muted">({cov.untested.length})</span>
          </h3>
          {cov.untested.length ? <CopyBtn text={untestedList} label="Copy list" /> : null}
        </div>
        {cov.untested.length ? (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[32rem] text-left text-xs">
              <thead className="text-muted">
                <tr>
                  <th className="py-2 pr-2 font-medium">Endpoint</th>
                  <th className="py-2 pr-2 font-medium">Flags</th>
                  <th className="py-2 font-medium">Seen</th>
                </tr>
              </thead>
              <tbody>
                {cov.untested.map((o) => (
                  <tr key={`${o.method} ${o.path}`} className="border-t border-border align-top">
                    <td className="py-1.5 pr-2 font-mono">
                      {o.method} {o.path}
                      {o.summary ? <span className="ml-2 font-sans text-subtle">{o.summary}</span> : null}
                    </td>
                    <td className="py-1.5 pr-2">
                      <span className="flex flex-wrap gap-1">
                        {o.secured ? <Badge tone="danger">auth</Badge> : null}
                        {o.write ? <Badge tone="warn">write</Badge> : null}
                        {o.deprecated ? <Badge tone="muted">deprecated</Badge> : null}
                      </span>
                    </td>
                    <td className="py-1.5 font-mono text-subtle">
                      {o.observedStatuses.length ? o.observedStatuses.join(",") : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-sm text-muted">Every declared endpoint was exercised.</p>
        )}
      </div>

      <div>
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-sm font-medium">
            Undocumented (shadow) endpoints <span className="text-muted">({cov.shadow.length})</span>
          </h3>
          {cov.shadow.length ? <CopyBtn text={shadowList} label="Copy list" /> : null}
        </div>
        {cov.shadow.length ? (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[28rem] text-left text-xs">
              <thead className="text-muted">
                <tr>
                  <th className="py-2 pr-2 font-medium">Route</th>
                  <th className="py-2 font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {cov.shadow.map((s) => (
                  <tr key={`${s.method} ${s.template}`} className="border-t border-border">
                    <td className="py-1.5 pr-2 font-mono">
                      {s.method} {s.template}
                    </td>
                    <td className="py-1.5 font-mono text-subtle">{s.statuses.join(",") || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-sm text-muted">No routes seen outside the declared spec.</p>
        )}
      </div>
    </div>
  );
}

function Badge({ tone, children }: { tone: "danger" | "warn" | "muted"; children: string }) {
  return (
    <span
      className={cn(
        "rounded-sm border px-1.5 py-0.5 font-mono text-[11px] uppercase",
        tone === "danger" ? "border-danger/40 text-danger" : tone === "warn" ? "border-warn/40 text-warn" : "border-border text-muted",
      )}
    >
      {children}
    </span>
  );
}
