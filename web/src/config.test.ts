import { describe, expect, it } from "vitest";

import { parsePortalConfig } from "./config";

describe("parsePortalConfig", () => {
  it("reads the settings and the role mapping", () => {
    const config = parsePortalConfig({
      issuer: "https://localhost:9443/application/o/sigil/",
      clientId: "sigil",
      apiBase: "https://localhost:8444",
      roleGroups: { admin: ["sigil-admins"], helpdesk: ["sigil-helpdesk"] },
    });
    expect(config.roleGroups).toEqual({ admin: ["sigil-admins"], helpdesk: ["sigil-helpdesk"] });
  });

  it("rejects a config without an issuer", () => {
    expect(() => parsePortalConfig({ clientId: "sigil", apiBase: "https://localhost:8444" })).toThrow(/issuer/);
  });

  it("rejects role groups that are not a list of strings", () => {
    expect(() =>
      parsePortalConfig({
        issuer: "https://idp.example/",
        clientId: "sigil",
        apiBase: "https://portal.example",
        roleGroups: { admin: "sigil-admins" },
      }),
    ).toThrow(/roleGroups.admin/);
  });
});
