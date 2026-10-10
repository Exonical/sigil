import type { ReactNode } from "react";

// A dashboard tile. It shows one number, or a list of label and count lines.
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
    <section className="rounded-lg border border-border bg-card p-4">
      <h2 className="text-sm text-muted-foreground">{title}</h2>
      {value !== undefined ? <p className="mt-2 text-3xl font-semibold">{String(value)}</p> : null}
      {lines ? (
        <ul className="mt-2 space-y-1 text-sm">
          {lines.length === 0 ? <li className="text-muted-foreground">None</li> : null}
          {lines.map(([label, count]) => (
            <li key={label} className="flex justify-between">
              <span>{label}</span>
              <span className="font-medium">{String(count)}</span>
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}
