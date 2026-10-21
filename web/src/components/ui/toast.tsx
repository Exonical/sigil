import * as ToastPrimitive from "@radix-ui/react-toast";
import * as React from "react";

import { cn } from "@/lib/utils";

export interface ToastMessage {
  id: number;
  title: string;
  description?: string;
  tone?: "info" | "error";
}

interface ToastContextValue {
  notify: (message: Omit<ToastMessage, "id">) => void;
}

const ToastContext = React.createContext<ToastContextValue | null>(null);

// Errors stay on screen longer than confirmations so they can be read.
const DURATION_MS = { info: 4000, error: 9000 } as const;

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [messages, setMessages] = React.useState<ToastMessage[]>([]);
  const nextId = React.useRef(1);

  const notify = React.useCallback((message: Omit<ToastMessage, "id">) => {
    const id = nextId.current++;
    setMessages((current) => [...current, { ...message, tone: message.tone ?? "info", id }]);
  }, []);

  const dismiss = (id: number) => setMessages((current) => current.filter((item) => item.id !== id));

  return (
    <ToastContext.Provider value={{ notify }}>
      <ToastPrimitive.Provider swipeDirection="right">
        {children}
        {messages.map((message) => (
          <ToastPrimitive.Root
            key={message.id}
            duration={DURATION_MS[message.tone ?? "info"]}
            onOpenChange={(open) => {
              if (!open) dismiss(message.id);
            }}
            className={cn(
              "pointer-events-auto grid w-[min(92vw,24rem)] gap-1 border bg-panel p-4",
              message.tone === "error" ? "border-danger" : "border-line-strong",
            )}
          >
            <ToastPrimitive.Title
              className={cn(
                "font-mono text-[11px] font-medium uppercase tracking-[0.12em]",
                message.tone === "error" ? "text-danger" : "text-text",
              )}
            >
              {message.title}
            </ToastPrimitive.Title>
            {message.description ? (
              <ToastPrimitive.Description className="text-sm text-text-2">
                {message.description}
              </ToastPrimitive.Description>
            ) : null}
          </ToastPrimitive.Root>
        ))}
        <ToastPrimitive.Viewport className="fixed bottom-4 right-4 z-[60] flex flex-col gap-2 outline-none" />
      </ToastPrimitive.Provider>
    </ToastContext.Provider>
  );
}

export function useToast(): ToastContextValue {
  const value = React.useContext(ToastContext);
  if (!value) throw new Error("useToast must be used inside ToastProvider");
  return value;
}
