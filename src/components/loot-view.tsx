import { CopyBtn } from "@/components/copy-btn";
import { useForge } from "@/lib/claimforge/store";
import { cn } from "@/lib/utils";

export function LootView() {
  const { workspace } = useForge();
  const wl = [
    workspace.wordlists.ids.join("\n"),
    workspace.wordlists.emails.join("\n"),
    workspace.wordlists.roles.join("\n"),
  ]
    .filter(Boolean)
    .join("\n");

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-medium">Harvest</h2>
        <CopyBtn text={wl} label="Copy wordlists" />
      </div>
      <ul className="flex flex-col gap-2">
        {workspace.loot.map((l, i) => (
          <li key={i} className="rounded-md border border-border bg-elevated p-3 text-sm">
            <div className="flex flex-wrap gap-2">
              <span
                className={cn(
                  "rounded-sm border px-1.5 py-0.5 font-mono text-[11px] uppercase",
                  l.severity === "high" || l.severity === "critical"
                    ? "border-danger/40 text-danger"
                    : "border-border text-muted",
                )}
              >
                {l.kind}
              </span>
              <span className="font-medium">{l.label}</span>
            </div>
            <p className="mt-1 font-mono text-xs text-muted">{l.value}</p>
            <p className="text-xs text-subtle">{l.where}</p>
          </li>
        ))}
        {!workspace.loot.length && <li className="text-sm text-muted">No loot heuristics fired.</li>}
      </ul>

      <div>
        <h2 className="mb-2 text-sm font-medium">Surface</h2>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[36rem] text-left text-xs">
            <thead className="text-muted">
              <tr>
                <th className="py-2 pr-2 font-medium">Route</th>
                <th className="py-2 pr-2 font-medium">Auth</th>
                <th className="py-2 pr-2 font-medium">Actors</th>
                <th className="py-2 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {workspace.surface.map((s) => (
                <tr key={s.method + s.template} className="border-t border-border">
                  <td className="py-1.5 pr-2 font-mono">
                    {s.method} {s.template}
                    {s.interesting.length ? <span className="ml-2 text-warn">{s.interesting.join(" ")}</span> : null}
                  </td>
                  <td className="py-1.5 pr-2">{s.auth ? "yes" : "no"}</td>
                  <td className="py-1.5 pr-2">{s.actors.join(",")}</td>
                  <td className="tabular py-1.5">{s.statuses.join(",")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div>
        <h2 className="mb-2 text-sm font-medium">JWTs</h2>
        <ul className="space-y-2">
          {workspace.jwts.map((j, i) => (
            <li key={i} className="rounded-md border border-border bg-bg p-2 font-mono text-xs">
              {j.actor} · alg={j.alg ?? "?"} · {j.source}
              {j.issues.map((x) => (
                <p key={x} className="text-danger">
                  {x}
                </p>
              ))}
            </li>
          ))}
        </ul>
      </div>

      <div>
        <h2 className="mb-2 text-sm font-medium">Cookies</h2>
        <ul className="space-y-2">
          {workspace.cookies.map((c, i) => (
            <li key={i} className="rounded-md border border-border bg-bg p-2 text-xs">
              <span className="font-mono">
                {c.actor} · {c.name}
              </span>
              <p className="text-muted">
                HttpOnly {String(c.flags.httpOnly)} · Secure {String(c.flags.secure)} · SameSite {c.flags.sameSite ?? "∅"}
              </p>
            </li>
          ))}
        </ul>
      </div>

      <p className="font-mono text-xs text-muted">Hosts: {workspace.wordlists.hosts.join(" ") || "—"}</p>
    </div>
  );
}
