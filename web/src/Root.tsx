import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import * as React from "react";
import { BrowserRouter } from "react-router";

import { AuthProvider, createUserManager, currentAccessToken } from "@/auth/AuthProvider";
import { ApiProvider, createAdminClient } from "@/api/client";
import { App, CallbackPage } from "@/app/App";
import { loadPortalConfig, type PortalConfig } from "@/config";
import { ToastProvider } from "@/components/ui/toast";

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1, refetchOnWindowFocus: false } },
});

// Dev-only: VITE_MOCK_API=1 serves fixture data without sign-in. The flag is a build-time constant, so production
// builds drop this branch and the mock module entirely.
const MockPortal = React.lazy(() => import("@/mock/MockPortal").then((module) => ({ default: module.MockPortal })));

function Fatal({ message }: { message: string }) {
  return <p className="p-6 text-destructive">{message}</p>;
}

// Loads the portal settings first, because sign-in and the API both depend on them.
function Bootstrap() {
  const [config, setConfig] = React.useState<PortalConfig | null>(null);
  const [failure, setFailure] = React.useState<string | null>(null);
  React.useEffect(() => {
    loadPortalConfig()
      .then(setConfig)
      .catch((error: unknown) => setFailure(error instanceof Error ? error.message : "The portal could not start."));
  }, []);
  if (failure) return <Fatal message={failure} />;
  if (!config) return <p className="p-6 text-muted-foreground">Loading the portal.</p>;
  return <Portal config={config} />;
}

function Portal({ config }: { config: PortalConfig }) {
  const userManager = React.useMemo(() => createUserManager(config, window.location.origin), [config]);
  const api = React.useMemo(
    () => createAdminClient(config.apiBase, () => currentAccessToken(userManager)),
    [config.apiBase, userManager],
  );
  const complete = React.useCallback(async () => {
    await userManager.signinRedirectCallback();
  }, [userManager]);

  return (
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <AuthProvider config={config} userManager={userManager}>
          <ApiProvider value={api}>
            <BrowserRouter>
              <App callback={<CallbackPage complete={complete} />} />
            </BrowserRouter>
          </ApiProvider>
        </AuthProvider>
      </ToastProvider>
    </QueryClientProvider>
  );
}

export function Root() {
  if (import.meta.env.VITE_MOCK_API === "1") {
    return (
      <React.Suspense fallback={<p className="p-6 text-text-2">Loading mock portal.</p>}>
        <MockPortal />
      </React.Suspense>
    );
  }
  return <Bootstrap />;
}
