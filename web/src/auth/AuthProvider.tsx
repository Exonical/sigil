import { InMemoryWebStorage, UserManager, WebStorageStateStore, type User } from "oidc-client-ts";
import * as React from "react";

import type { PortalConfig } from "@/config";

import { groupsFromProfile, rolesFor, type Role } from "./roles";

export type AuthStatus = "loading" | "signedOut" | "signedIn";

export interface AuthState {
  status: AuthStatus;
  displayName: string;
  roles: Role[];
  signIn: () => Promise<void>;
  signOut: () => Promise<void>;
  // Returns a fresh access token, renewing it with the in-memory refresh token when it is close to expiry.
  getAccessToken: () => Promise<string | undefined>;
}

export const AuthContext = React.createContext<AuthState | null>(null);

export function createUserManager(config: PortalConfig, origin: string): UserManager {
  return new UserManager({
    authority: config.issuer,
    client_id: config.clientId,
    redirect_uri: `${origin}/callback`,
    post_logout_redirect_uri: `${origin}/`,
    response_type: "code",
    scope: "openid profile email offline_access",
    // Tokens live in memory only. The PKCE state survives the redirect to the identity provider in
    // sessionStorage; it holds no tokens.
    userStore: new WebStorageStateStore({ store: new InMemoryWebStorage() }),
    stateStore: new WebStorageStateStore({ store: window.sessionStorage }),
    automaticSilentRenew: true,
  });
}

// Returns a usable access token. A token about to expire is renewed first with the in-memory refresh token.
export async function currentAccessToken(userManager: UserManager): Promise<string | undefined> {
  const current = await userManager.getUser();
  if (!current) return undefined;
  if (current.expires_in !== undefined && current.expires_in < 60) {
    const renewed = await userManager.signinSilent().catch(() => null);
    return renewed?.access_token;
  }
  return current.access_token;
}

export function displayNameOf(user: User): string {
  const profile = user.profile as Record<string, unknown>;
  const name = profile.preferred_username ?? profile.name ?? profile.email;
  return typeof name === "string" ? name : "Signed in";
}

export function AuthProvider({
  config,
  userManager,
  children,
}: {
  config: PortalConfig;
  userManager: UserManager;
  children: React.ReactNode;
}) {
  const [status, setStatus] = React.useState<AuthStatus>("loading");
  const [user, setUser] = React.useState<User | null>(null);

  React.useEffect(() => {
    let active = true;
    void userManager.getUser().then((loaded) => {
      if (!active) return;
      const usable = loaded && !loaded.expired ? loaded : null;
      setUser(usable);
      setStatus(usable ? "signedIn" : "signedOut");
    });
    const onLoaded = (loaded: User) => {
      setUser(loaded);
      setStatus("signedIn");
    };
    const onSignedOut = () => {
      setUser(null);
      setStatus("signedOut");
    };
    userManager.events.addUserLoaded(onLoaded);
    userManager.events.addUserUnloaded(onSignedOut);
    userManager.events.addAccessTokenExpired(onSignedOut);
    return () => {
      active = false;
      userManager.events.removeUserLoaded(onLoaded);
      userManager.events.removeUserUnloaded(onSignedOut);
      userManager.events.removeAccessTokenExpired(onSignedOut);
    };
  }, [userManager]);

  const value = React.useMemo<AuthState>(() => {
    const groups = user ? groupsFromProfile(user.profile as Record<string, unknown>) : [];
    return {
      status,
      displayName: user ? displayNameOf(user) : "",
      roles: rolesFor(groups, config.roleGroups),
      signIn: () => userManager.signinRedirect(),
      signOut: async () => {
        await userManager.removeUser();
        await userManager.signoutRedirect().catch(() => undefined);
      },
      getAccessToken: () => currentAccessToken(userManager),

    };
  }, [status, user, config.roleGroups, userManager]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const value = React.useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside AuthProvider");
  return value;
}
