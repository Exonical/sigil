import type { HTMLAttributes } from "react";

import { cn } from "@/lib/utils";

// A status indicator: a small square and uppercase mono text in a semantic colour. The GUI uses the same
// visual (`.slot-key-state` and `.sg-status` in crates/sigil-gui/src/theme.css). See design/README.md.
import type { StatusTone } from "@/lib/status";

export type { StatusTone };

const TONE_CLASS: Record<StatusTone, string> = {
  ok: "text-ok",
  warn: "text-warn",
  danger: "text-danger",
  neutral: "text-text-3",
};

export function StatusBadge({
  tone = "neutral",
  className,
  children,
  ...props
}: HTMLAttributes<HTMLSpanElement> & { tone?: StatusTone }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-2 whitespace-nowrap font-mono text-[11px] font-medium uppercase tracking-[0.12em]",
        TONE_CLASS[tone],
        className,
      )}
      {...props}
    >
      <span aria-hidden="true" className="inline-block h-[7px] w-[7px] bg-current" />
      {children}
    </span>
  );
}
