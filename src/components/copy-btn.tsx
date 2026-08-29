import { Check, Copy } from "lucide-react";
import { useState } from "react";
import { cn } from "@/lib/utils";

export function CopyBtn({ text, label = "Copy" }: { text: string; label?: string }) {
  const [ok, setOk] = useState(false);
  return (
    <button
      type="button"
      aria-label={ok ? "Copied" : label}
      className={cn(
        "inline-flex min-h-11 items-center gap-1.5 rounded-md border border-border px-3 text-xs font-medium",
        "bg-elevated text-fg transition-colors duration-150 hover:border-accent",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent",
      )}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
        } catch {
          const ta = document.createElement("textarea");
          ta.value = text;
          document.body.appendChild(ta);
          ta.select();
          document.execCommand("copy");
          ta.remove();
        }
        setOk(true);
        window.setTimeout(() => setOk(false), 1200);
      }}
    >
      {ok ? <Check className="size-3.5" aria-hidden /> : <Copy className="size-3.5" aria-hidden />}
      {ok ? "Copied" : label}
    </button>
  );
}
