import { cva, type VariantProps } from "class-variance-authority";
import type { HTMLAttributes } from "react";

import { cn } from "@/lib/utils";

// A status tag: uppercase mono text in a hairline box, with a tint for the status colour.
const badgeVariants = cva(
  "inline-flex items-center gap-1.5 rounded-md border px-1.5 py-0.5 font-mono text-[10px] font-medium uppercase tracking-[0.12em]",
  {
    variants: {
      variant: {
        default: "border-accent bg-accent-tint text-accent",
        secondary: "border-line-strong text-text-2",
        destructive: "border-danger bg-danger-tint text-danger",
        outline: "border-line text-text",
      },
    },
    defaultVariants: { variant: "secondary" },
  },
);

export interface BadgeProps extends HTMLAttributes<HTMLDivElement>, VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />;
}
