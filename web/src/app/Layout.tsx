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
      <aside className="border-b border-border bg-card p-4 md:border-b-0 md:border-r">
        <div className="mb-4 font-semibold tracking-tight">Sigil admin</div>
        <nav aria-label="Main" className="flex flex-wrap gap-1 md:flex-col">
          {links.map((link) => (
            <NavLink
              key={link.to}
              to={link.to}
              end={link.to === "/"}
              className={({ isActive }) =>
                cn(
                  "rounded-md px-3 py-2 text-sm hover:bg-muted",
                  isActive ? "bg-muted font-medium" : "text-muted-foreground",
                )
              }
            >
              {link.label}
            </NavLink>
          ))}
        </nav>
        <div className="mt-6 space-y-2 text-sm">
          <div className="flex items-center gap-2">
            <span className="truncate" title={auth.displayName}>
              {auth.displayName}
            </span>
            <Badge>{role}</Badge>
          </div>
          <Button variant="outline" size="sm" onClick={() => void auth.signOut()}>
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
    <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
      <h1 className="text-xl font-semibold">{title}</h1>
      {children}
    </div>
  );
}
