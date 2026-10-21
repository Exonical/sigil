import { describe, expect, it } from "vitest";

import { groupsFromProfile, isAdmin, isOperator, rolesFor } from "./roles";

const mapping = { admin: ["sigil-admins"], helpdesk: ["sigil-helpdesk"] };

describe("rolesFor", () => {
  it("maps admin and helpdesk groups to roles", () => {
    expect(rolesFor(["sigil-admins"], mapping)).toEqual(["admin"]);
    expect(rolesFor(["sigil-helpdesk"], mapping)).toEqual(["helpdesk"]);
    expect(rolesFor(["sigil-admins", "sigil-helpdesk"], mapping)).toEqual(["admin", "helpdesk"]);
  });

  it("grants no role to users outside the mapped groups", () => {
    expect(rolesFor(["everyone"], mapping)).toEqual([]);
    expect(rolesFor([], mapping)).toEqual([]);
  });
});

describe("role checks", () => {
  it("treats only admin as admin, and admin or helpdesk as an operator", () => {
    expect(isAdmin(["admin"])).toBe(true);
    expect(isAdmin(["helpdesk"])).toBe(false);
    expect(isOperator(["helpdesk"])).toBe(true);
    expect(isOperator([])).toBe(false);
  });
});

describe("groupsFromProfile", () => {
  it("accepts a list or a single string for the groups claim", () => {
    expect(groupsFromProfile({ groups: ["a", "b"] })).toEqual(["a", "b"]);
    expect(groupsFromProfile({ groups: "a" })).toEqual(["a"]);
    expect(groupsFromProfile({})).toEqual([]);
  });
});
