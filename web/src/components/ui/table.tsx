import * as React from "react";

import { cn } from "@/lib/utils";

// Dense, data-forward tables: hairline rows, mono uppercase column headers.
export const Table = ({ className, ...props }: React.HTMLAttributes<HTMLTableElement>) => (
  <div className="w-full overflow-x-auto border border-line bg-panel">
    <table className={cn("w-full caption-bottom text-[13px] tabular-nums", className)} {...props} />
  </div>
);

export const TableHeader = (props: React.HTMLAttributes<HTMLTableSectionElement>) => (
  <thead className="bg-raised" {...props} />
);

export const TableBody = (props: React.HTMLAttributes<HTMLTableSectionElement>) => <tbody {...props} />;

export const TableRow = ({ className, ...props }: React.HTMLAttributes<HTMLTableRowElement>) => (
  <tr className={cn("border-b border-line transition-colors hover:bg-raised", className)} {...props} />
);

export const TableHead = ({ className, ...props }: React.ThHTMLAttributes<HTMLTableCellElement>) => (
  <th
    className={cn(
      "h-9 whitespace-nowrap px-3 text-left align-middle font-mono text-[11px] font-medium uppercase tracking-[0.12em] text-text-2",
      className,
    )}
    {...props}
  />
);

export const TableCell = ({ className, ...props }: React.TdHTMLAttributes<HTMLTableCellElement>) => (
  <td className={cn("px-3 py-2 align-middle text-text", className)} {...props} />
);
