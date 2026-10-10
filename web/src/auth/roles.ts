import type { RoleGroups } from "@/config";

export type Role = "admin" | "helpdesk";

// Mirrors the backend rule in internal/admin: a user holds a role when any of their groups is mapped to it.
// The browser uses this only to show or hide actions. The API enforces the same rule on every call.
export function rolesFor(groups: readonly string[], mapping: RoleGroups): Role[] {
  const roles: Role[] = [];
  if (groups.some((group) => mapping.admin.includes(group))) roles.push("admin");
  if (groups.some((group) => mapping.helpdesk.includes(group))) roles.push("helpdesk");
  return roles;
}

export function isAdmin(roles: readonly Role[]): boolean {
  return roles.includes("admin");
}

export function isOperator(roles: readonly Role[]): boolean {
  return roles.includes("admin") || roles.includes("helpdesk");
}

// Reads the groups claim from an OIDC profile, accepting a single string as well as a list.
export function groupsFromProfile(profile: Record<string, unknown>): string[] {
  const groups = profile.groups;
  if (typeof groups === "string") return [groups];
  if (Array.isArray(groups)) return groups.filter((group): group is string => typeof group === "string");
  return [];
}
