import * as React from "react";
import { Navigate, Route, Routes, useNavigate } from "react-router";

import { useAuth } from "@/auth/AuthProvider";
import { Button } from "@/components/ui/button";
import { Audit } from "@/pages/Audit";
import { Certificates } from "@/pages/Certificates";
import { Dashboard } from "@/pages/Dashboard";
import { Stations } from "@/pages/Stations";
import { TokenDetail } from "@/pages/TokenDetail";
import { Tokens } from "@/pages/Tokens";
import { Users } from "@/pages/Users";

import { Layout } from "./Layout";

export function App({ callback }: { callback: React.ReactNode }) {
  return (
    <Routes>
      <Route path="/callback" element={callback} />
      <Route element={<RequireSignedIn />}>
        <Route element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="tokens" element={<Tokens />} />
          <Route path="tokens/:serial" element={<TokenDetail />} />
          <Route path="certificates" element={<Certificates />} />
          <Route path="stations" element={<Stations />} />
          <Route path="users" element={<Users />} />
          <Route path="audit" element={<Audit />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Route>
    </Routes>
  );
}

// Every page needs a signed-in user. The API also rejects requests without a valid token.
function RequireSignedIn() {
  const auth = useAuth();
  if (auth.status === "loading") {
    return <p className="p-6 text-muted-foreground">Loading.</p>;
  }
  if (auth.status === "signedOut") {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-4 p-6">
        <h1 className="text-xl font-semibold">Sigil admin portal</h1>
        <p className="text-sm text-muted-foreground">Sign in with your Sigil account to continue.</p>
        <Button onClick={() => void auth.signIn()}>Sign in</Button>
      </div>
    );
  }
  return <Outlet />;
}

import { Outlet } from "react-router";

// Completes the sign-in redirect and returns to the page the user started from.
export function CallbackPage({ complete }: { complete: () => Promise<void> }) {
  const navigate = useNavigate();
  const [failure, setFailure] = React.useState<string | null>(null);
  React.useEffect(() => {
    let active = true;
    complete()
      .then(() => {
        if (active) navigate("/", { replace: true });
      })
      .catch((error: unknown) => {
        if (active) setFailure(error instanceof Error ? error.message : "Sign-in did not complete.");
      });
    return () => {
      active = false;
    };
  }, [complete, navigate]);
  if (failure) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-4 p-6">
        <p className="text-destructive">{failure}</p>
        <Button variant="outline" onClick={() => navigate("/", { replace: true })}>
          Back to the portal
        </Button>
      </div>
    );
  }
  return <p className="p-6 text-muted-foreground">Completing sign-in.</p>;
}
