import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import * as React from "react";

import { cn } from "@/lib/utils";

// Rectangular, mono, uppercase. Primary is the accent fill; secondary a hairline outline; danger a red outline.
const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md font-mono text-[11px] font-medium uppercase tracking-[0.12em] transition-colors disabled:pointer-events-none disabled:opacity-40",
  {
    variants: {
      variant: {
        default: "border border-accent bg-accent text-accent-ink hover:brightness-110",
        destructive: "border border-danger bg-transparent text-danger hover:bg-danger-tint",
        outline: "border border-line-strong bg-transparent text-text hover:bg-raised",
        ghost: "border border-transparent bg-transparent text-text-2 hover:bg-raised hover:text-text",
      },
      size: {
        default: "h-9 px-4",
        sm: "h-8 px-3",
      },
    },
    defaultVariants: { variant: "default", size: "default" },
  },
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button";
    return <Comp ref={ref} className={cn(buttonVariants({ variant, size }), className)} {...props} />;
  },
);
Button.displayName = "Button";
