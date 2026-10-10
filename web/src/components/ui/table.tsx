import * as React from "react";

import { cn } from "@/lib/utils";

export const Table = ({ className, ...props }: React.HTMLAttributes<HTMLTableElement>) => (
  <div className="w-full overflow-x-auto">
    <table className={cn("w-full caption-bottom text-sm", className)} {...props} />
  </div>
);

export const TableHeader = (props: React.HTMLAttributes<HTMLTableSectionElement>) => (
  <thead className="border-b border-border" {...props} />
);

export const TableBody = (props: React.HTMLAttributes<HTMLTableSectionElement>) => <tbody {...props} />;

export const TableRow = ({ className, ...props }: React.HTMLAttributes<HTMLTableRowElement>) => (
  <tr className={cn("border-b border-border transition-colors hover:bg-muted/50", className)} {...props} />
);

export const TableHead = ({ className, ...props }: React.ThHTMLAttributes<HTMLTableCellElement>) => (
  <th
    className={cn("h-10 px-3 text-left align-middle text-xs font-medium text-muted-foreground", className)}
    {...props}
  />
);

export const TableCell = ({ className, ...props }: React.TdHTMLAttributes<HTMLTableCellElement>) => (
  <td className={cn("px-3 py-2 align-middle", className)} {...props} />
);
