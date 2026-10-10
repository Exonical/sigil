import * as DialogPrimitive from "@radix-ui/react-dialog";
import * as React from "react";

import { cn } from "@/lib/utils";

export const Dialog = DialogPrimitive.Root;
export const DialogTrigger = DialogPrimitive.Trigger;
export const DialogClose = DialogPrimitive.Close;

export const DialogContent = React.forwardRef<
  React.ElementRef<typeof DialogPrimitive.Content>,
  React.ComponentPropsWithoutRef<typeof DialogPrimitive.Content>
>(({ className, children, ...props }, ref) => (
  <DialogPrimitive.Portal>
    <DialogPrimitive.Overlay className="fixed inset-0 z-50 bg-black/60" />
    <DialogPrimitive.Content
      ref={ref}
      className={cn(
        "fixed left-1/2 top-1/2 z-50 grid w-[min(92vw,28rem)] -translate-x-1/2 -translate-y-1/2 gap-4 rounded-lg border border-border bg-card p-6 shadow-lg",
        className,
      )}
      {...props}
    >
      {children}
    </DialogPrimitive.Content>
  </DialogPrimitive.Portal>
));
DialogContent.displayName = "DialogContent";

export const DialogTitle = ({ className, ...props }: React.ComponentPropsWithoutRef<typeof DialogPrimitive.Title>) => (
  <DialogPrimitive.Title className={cn("text-lg font-semibold", className)} {...props} />
);

export const DialogDescription = ({
  className,
  ...props
}: React.ComponentPropsWithoutRef<typeof DialogPrimitive.Description>) => (
  <DialogPrimitive.Description className={cn("text-sm text-muted-foreground", className)} {...props} />
);
