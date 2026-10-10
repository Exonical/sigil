import { createClient, ConnectError, type Client, type Interceptor } from "@connectrpc/connect";
import { createConnectTransport } from "@connectrpc/connect-web";
import * as React from "react";

import { AdminService } from "@/gen/sigil/admin/v1/admin_pb";

export type AdminClient = Client<typeof AdminService>;

// Adds the bearer token to every call. The server checks the token and the role on each RPC.
export function createAdminClient(apiBase: string, getAccessToken: () => Promise<string | undefined>): AdminClient {
  const authorize: Interceptor = (next) => async (request) => {
    const token = await getAccessToken();
    if (token) request.header.set("Authorization", `Bearer ${token}`);
    return next(request);
  };
  const transport = createConnectTransport({ baseUrl: apiBase, interceptors: [authorize] });
  return createClient(AdminService, transport);
}

const ApiContext = React.createContext<AdminClient | null>(null);

export const ApiProvider = ApiContext.Provider;

export function useApi(): AdminClient {
  const value = React.useContext(ApiContext);
  if (!value) throw new Error("useApi must be used inside ApiProvider");
  return value;
}

// The server's message is shown as is; it never contains secrets and is written for operators.
export function errorMessage(error: unknown): string {
  return ConnectError.from(error).rawMessage;
}
