// Dev-only portal with fixture data and no sign-in. Started by `VITE_MOCK_API=1 npm run dev`.
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter } from "react-router";

import { AuthContext, type AuthState } from "@/auth/AuthProvider";
import { ApiProvider, type AdminClient } from "@/api/client";
import { App } from "@/app/App";
import { ToastProvider } from "@/components/ui/toast";

import { mockData, mockUser } from "./fixtures";

const auth: AuthState = {
  status: "signedIn",
  displayName: mockUser.username,
  roles: ["admin"],
  signIn: async () => undefined,
  signOut: async () => undefined,
  getAccessToken: async () => "mock-token",
};

const ok = <T,>(value: T): Promise<T> => Promise.resolve(value);

// Only the calls the pages make. Mutations succeed without changing fixture data.
const client = {
  getDashboard: () => ok(mockData.dashboard),
  listTokens: ({ search, status }: { search: string; status: string }) => {
    const needle = search.trim().toLowerCase();
    const tokens = mockData.tokens.filter(
      (token) =>
        (status === "" || token.status === status) &&
        (needle === "" ||
          token.serial.includes(needle) ||
          token.nickname.toLowerCase().includes(needle) ||
          (token.assignedUser?.username ?? "").includes(needle)),
    );
    return ok({ tokens, total: BigInt(tokens.length) });
  },
  getToken: ({ serial }: { serial: string }) => {
    const detail = mockData.tokenDetail(serial);
    return detail ? ok(detail) : Promise.reject(new Error(`The token ${serial} is not in inventory.`));
  },
  listCertificates: () => ok({ certificates: mockData.certificates, total: BigInt(mockData.certificates.length) }),
  listStations: () => ok({ stations: mockData.stations }),
  listUsers: () => ok({ users: mockData.users, total: BigInt(mockData.users.length) }),
  listAudit: () => ok({ events: mockData.audit, nextBeforeSeq: 0n }),
  verifyAudit: () => ok({ ok: true, eventsChecked: BigInt(mockData.audit.length), failure: "" }),
  assignToken: () => ok({}),
  unassignToken: () => ok({}),
  setNickname: () => ok({}),
  reportLost: () => ok({}),
  markFound: () => ok({ reEnrollmentRequired: false }),
  deleteKey: () => ok({ revoked: 0, failedCertificateIds: [] }),
  revokeCertificate: () => ok({}),
  addStation: () => ok({}),
  setStationStatus: () => ok({}),
} as unknown as AdminClient;

const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } } });

export function MockPortal() {
  return (
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <AuthContext.Provider value={auth}>
          <ApiProvider value={client}>
            <BrowserRouter>
              <App callback={<p className="p-6 text-text-2">Mock mode has no sign-in callback.</p>} />
            </BrowserRouter>
          </ApiProvider>
        </AuthContext.Provider>
      </ToastProvider>
    </QueryClientProvider>
  );
}
