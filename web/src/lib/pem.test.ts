import { describe, expect, it } from "vitest";

import { derToPem } from "./pem";

describe("derToPem", () => {
  it("wraps DER bytes in a CERTIFICATE block with 64-character lines", () => {
    const der = new Uint8Array(100).map((_, index) => index);
    const pem = derToPem(der);
    const lines = pem.trim().split("\n");
    expect(lines[0]).toBe("-----BEGIN CERTIFICATE-----");
    expect(lines.at(-1)).toBe("-----END CERTIFICATE-----");
    const body = lines.slice(1, -1);
    expect(body.every((line) => line.length <= 64)).toBe(true);
    expect(pem.endsWith("\n")).toBe(true);
  });

  it("round-trips the bytes through base64", () => {
    const der = Uint8Array.from([0x30, 0x03, 0x02, 0x01, 0xff]);
    const body = derToPem(der).split("\n").slice(1, -2).join("");
    expect(Array.from(Uint8Array.from(atob(body), (char) => char.charCodeAt(0)))).toEqual(Array.from(der));
  });
});
