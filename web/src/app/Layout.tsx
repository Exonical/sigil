import * as React from "react";
import { NavLink, Outlet } from "react-router";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/auth/AuthProvider";
import { isAdmin } from "@/auth/roles";
import { cn } from "@/lib/utils";

const links = [
  { to: "/", label: "Dashboard", adminOnly: false },
  { to: "/tokens", label: "Tokens", adminOnly: false },
  { to: "/certificates", label: "Certificates", adminOnly: false },
  { to: "/stations", label: "Stations", adminOnly: false },
  { to: "/users", label: "Users", adminOnly: false },
  { to: "/audit", label: "Audit", adminOnly: false },
];

export function Layout() {
  const auth = useAuth();
  const role = isAdmin(auth.roles) ? "Admin" : "Helpdesk";
  return (
    <div className="min-h-screen md:grid md:grid-cols-[14rem_1fr]">
      <aside className="flex flex-col border-b border-line-strong bg-panel md:border-b-0 md:border-r">
        <div className="flex items-center gap-2 border-b border-line px-4 py-4">
          <span className="h-2 w-2 bg-accent" aria-hidden="true" />
          <span className="font-mono text-[11px] font-medium uppercase tracking-[0.16em] text-text">Sigil</span>
          <span className="font-mono text-[11px] uppercase tracking-[0.16em] text-text-3">Admin</span>
        </div>
        <nav aria-label="Main" className="flex flex-wrap gap-px p-2 md:flex-col">
          {links.map((link) => (
            <NavLink
              key={link.to}
              to={link.to}
              end={link.to === "/"}
              className={({ isActive }) =>
                cn(
                  "border-l-2 px-3 py-2 font-mono text-[11px] font-medium uppercase tracking-[0.12em] hover:bg-raised hover:text-text",
                  isActive ? "border-accent bg-raised text-text" : "border-transparent text-text-2",
                )
              }
            >
              {link.label}
            </NavLink>
          ))}
        </nav>
        <div className="mt-auto space-y-3 border-t border-line p-4">
          <div className="space-y-1">
            <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-text-3">Signed in</div>
            <div className="truncate text-sm text-text" title={auth.displayName}>
              {auth.displayName}
            </div>
            <Badge>{role}</Badge>
          </div>
          <Button variant="outline" size="sm" className="w-full" onClick={() => void auth.signOut()}>
            Sign out
          </Button>
        </div>
      </aside>
      <main className="min-w-0 p-4 md:p-6">
        <Outlet />
      </main>
    </div>
  );
}

// Shows a heading and an optional action area on every page.
export function PageHeader({ title, children }: { title: string; children?: React.ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-2 border-b border-line pb-3">
      <h1 className="font-sans text-[28px] font-semibold leading-none tracking-[-0.02em] text-text">{title}</h1>
      {children}
    </div>
  );
}
