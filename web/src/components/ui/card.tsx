import type { ReactNode } from "react";

// A dashboard tile: a hairline panel with a mono label, a large number, and optional count lines.
export function Card({
  title,
  value,
  lines,
}: {
  title: string;
  value?: bigint | number;
  lines?: [string, bigint | number][];
}): ReactNode {
  return (
    <section className="relative border border-line bg-panel p-4">
      <h2 className="font-mono text-[11px] font-medium uppercase tracking-[0.12em] text-text-3">{title}</h2>
      {value !== undefined ? (
        <p className="mt-2 font-sans text-[32px] font-semibold leading-none tracking-[-0.02em] text-text">
          {String(value)}
        </p>
      ) : null}
      {lines ? (
        <ul className="mt-3 divide-y divide-line border-t border-line text-[13px]">
          {lines.length === 0 ? <li className="py-2 text-text-3">None</li> : null}
          {lines.map(([label, count]) => (
            <li key={label} className="flex justify-between py-1.5">
              <span className="font-mono text-[12px] uppercase tracking-[0.08em] text-text-2">{label}</span>
              <span className="font-mono font-medium text-text">{String(count)}</span>
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}
