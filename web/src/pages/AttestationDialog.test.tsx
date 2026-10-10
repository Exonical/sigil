import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiProvider, type AdminClient } from "@/api/client";

import { AttestationDialog } from "./AttestationDialog";

const summary = {
  present: true,
  attestedSerial: "39192733",
  firmware: "5.7.4",
  slot: "9a",
  pinPolicy: "02",
  touchPolicy: "01",
  root: "Yubico Attestation Root 1",
};

function renderDialog(response: unknown) {
  const client = { getCertificateAttestation: vi.fn(async () => response) } as unknown as AdminClient;
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <ApiProvider value={client}>
        <AttestationDialog certificateId="c-1" open onOpenChange={() => undefined} />
      </ApiProvider>
    </QueryClientProvider>,
  );
  return client;
}

describe("AttestationDialog", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows the verified status, the chain root and the attested fields", async () => {
    renderDialog({
      attestationDer: new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x01]),
      attestationIntermediateDer: new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x02]),
      summary,
    });
    expect(await screen.findByText("Verified")).toBeInTheDocument();
    expect(screen.getByText("Yubico Attestation Root 1")).toBeInTheDocument();
    expect(screen.getByText("39192733")).toBeInTheDocument();
    expect(screen.getByText("5.7.4")).toBeInTheDocument();
  });

  it("reports a certificate with no stored attestation and disables both downloads", async () => {
    renderDialog({
      attestationDer: new Uint8Array(),
      attestationIntermediateDer: new Uint8Array(),
      summary: { ...summary, present: false, root: "" },
    });
    expect(await screen.findByText("Not attested")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Download attestation" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Download slot F9" })).toBeDisabled();
  });

  it("downloads the attestation as PEM generated in the browser", async () => {
    const created: Blob[] = [];
    const createObjectURL = vi.fn((blob: Blob) => {
      created.push(blob);
      return "blob:test";
    });
    Object.defineProperty(URL, "createObjectURL", { configurable: true, value: createObjectURL });
    Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: vi.fn() });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);

    renderDialog({
      attestationDer: new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x01]),
      attestationIntermediateDer: new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x02]),
      summary,
    });
    const button = await screen.findByRole("button", { name: "Download attestation" });
    await waitFor(() => expect(button).toBeEnabled());
    await userEvent.click(button);

    expect(click).toHaveBeenCalledTimes(1);
    expect(created).toHaveLength(1);
    const text = await created[0]!.text();
    expect(text.startsWith("-----BEGIN CERTIFICATE-----\n")).toBe(true);
    expect(text.trim().endsWith("-----END CERTIFICATE-----")).toBe(true);
  });
});
