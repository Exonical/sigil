import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router";
import { describe, expect, it, vi } from "vitest";

import { AuthContext, type AuthState } from "@/auth/AuthProvider";
import type { Role } from "@/auth/roles";
import { ApiProvider, type AdminClient } from "@/api/client";
import { ToastProvider } from "@/components/ui/toast";

import { TokenDetail } from "./TokenDetail";

const detailResponse = {
  token: {
    id: "tok-1",
    vendor: "Yubico",
    model: "YubiKey 5 FIPS",
    serial: "39192733",
    nickname: "front desk",
    status: "active",
    assignedUser: { id: "u-1", username: "admin1", email: "admin1@example.test", displayName: "Admin" },
    lostAtUnix: 0n,
    lastSeenUnix: 1_700_000_000n,
    activeCertificates: 1n,
  },
  certificates: [
    { id: "c-1", slot: "9a", profile: "piv-authentication", subject: "CN=admin1", status: "active", notAfterUnix: 1_900_000_000n },
  ],
  // Escrow metadata only. The fixture has no value fields at all, as the API never sends them.
  escrow: [{ kind: "puk", version: 2, state: "active", createdAtUnix: 1_700_000_000n, activatedAtUnix: 1_700_000_100n }],
  audit: [],
};

function auth(roles: Role[]): AuthState {
  return {
    status: "signedIn",
    displayName: "tester",
    roles,
    signIn: vi.fn(async () => undefined),
    signOut: vi.fn(async () => undefined),
    getAccessToken: vi.fn(async () => "token"),
  };
}

function renderPage(roles: Role[], client: Partial<Record<string, unknown>>) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const api = client as unknown as AdminClient;
  return render(
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <AuthContext.Provider value={auth(roles)}>
          <ApiProvider value={api}>
            <MemoryRouter initialEntries={["/tokens/39192733"]}>
              <Routes>
                <Route path="/tokens/:serial" element={<TokenDetail />} />
              </Routes>
            </MemoryRouter>
          </ApiProvider>
        </AuthContext.Provider>
      </ToastProvider>
    </QueryClientProvider>,
  );
}

function mockClient() {
  return {
    getToken: vi.fn(async () => detailResponse),
    reportLost: vi.fn(async () => ({})),
    deleteKey: vi.fn(async () => ({ revoked: 1, failedCertificateIds: [] })),
  };
}

describe("TokenDetail", () => {
  it("renders the token, its certificates, and escrow metadata without values", async () => {
    renderPage(["helpdesk"], mockClient());
    expect(await screen.findByRole("heading", { name: "Token 39192733" })).toBeInTheDocument();
    expect(screen.getByText("admin1")).toBeInTheDocument();
    const escrow = screen.getByRole("heading", { name: "Escrow" }).parentElement as HTMLElement;
    expect(within(escrow).getByText("puk")).toBeInTheDocument();
    expect(within(escrow).getByText("active")).toBeInTheDocument();
    expect(within(escrow).getByText(/Metadata only/)).toBeInTheDocument();
  });

  it("hides Delete key from helpdesk users", async () => {
    renderPage(["helpdesk"], mockClient());
    await screen.findByRole("heading", { name: "Token 39192733" });
    expect(screen.queryByRole("button", { name: "Delete key" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Report lost" })).toBeInTheDocument();
  });

  it("shows Delete key to admins, and it stays disabled until the serial is typed", async () => {
    const user = userEvent.setup();
    const client = mockClient();
    renderPage(["admin"], client);
    await screen.findByRole("heading", { name: "Token 39192733" });
    await user.click(screen.getByRole("button", { name: "Delete key" }));
    const confirm = await screen.findByRole("textbox", { name: "Type the serial to confirm" });
    const submit = screen.getAllByRole("button", { name: "Delete key" }).at(-1) as HTMLElement;
    expect(submit).toBeDisabled();
    await user.type(confirm, "39192733");
    expect(submit).toBeEnabled();
    await user.click(submit);
    expect(client.deleteKey).toHaveBeenCalledWith({ token: { vendor: "Yubico", serial: "39192733" }, confirmSerial: "39192733" });
  });

  it("reports the token lost through the API", async () => {
    const user = userEvent.setup();
    const client = mockClient();
    renderPage(["helpdesk"], client);
    await user.click(await screen.findByRole("button", { name: "Report lost" }));
    expect(client.reportLost).toHaveBeenCalledWith({ vendor: "Yubico", serial: "39192733" });
  });
});
