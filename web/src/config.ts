// Portal settings served by the backend at /portal-config.json. One build works everywhere because nothing
// environment-specific is compiled in.
export interface RoleGroups {
  admin: string[];
  helpdesk: string[];
}

export interface PortalConfig {
  issuer: string;
  clientId: string;
  apiBase: string;
  roleGroups: RoleGroups;
}

function stringList(value: unknown, field: string): string[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    throw new Error(`portal-config.json: ${field} must be a list of strings`);
  }
  return value;
}

export function parsePortalConfig(value: unknown): PortalConfig {
  if (typeof value !== "object" || value === null) {
    throw new Error("portal-config.json must be a JSON object");
  }
  const record = value as Record<string, unknown>;
  for (const field of ["issuer", "clientId", "apiBase"] as const) {
    if (typeof record[field] !== "string" || record[field] === "") {
      throw new Error(`portal-config.json: ${field} is required`);
    }
  }
  const groups = (record.roleGroups ?? {}) as Record<string, unknown>;
  return {
    issuer: record.issuer as string,
    clientId: record.clientId as string,
    apiBase: record.apiBase as string,
    roleGroups: {
      admin: stringList(groups.admin, "roleGroups.admin"),
      helpdesk: stringList(groups.helpdesk, "roleGroups.helpdesk"),
    },
  };
}

export async function loadPortalConfig(fetcher: typeof fetch = fetch): Promise<PortalConfig> {
  const response = await fetcher("/portal-config.json", { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`The portal configuration could not be loaded (HTTP ${response.status}).`);
  }
  return parsePortalConfig(await response.json());
}
