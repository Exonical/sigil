import { useQuery } from "@tanstack/react-query";

import { errorMessage, useApi } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { StatusBadge } from "@/components/ui/status";
import { downloadText, derToPem } from "@/lib/pem";

// The stored attestation for one certificate: a VERIFIED status, the chain root, the attested fields, and PEM
// downloads of the attestation certificate and the slot F9 certificate that signed it.
export function AttestationDialog({
  certificateId,
  open,
  onOpenChange,
}: {
  certificateId: string | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const api = useApi();
  const attestation = useQuery({
    queryKey: ["certificate-attestation", certificateId],
    queryFn: () => api.getCertificateAttestation({ certificateId: certificateId ?? "" }),
    enabled: open && certificateId !== null,
  });

  const data = attestation.data;
  const summary = data?.summary;
  const attestedPem = data && data.attestationDer.length > 0 ? derToPem(data.attestationDer) : null;
  const intermediatePem =
    data && data.attestationIntermediateDer.length > 0 ? derToPem(data.attestationIntermediateDer) : null;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogTitle>Attestation</DialogTitle>
        <DialogDescription>
          The chain was verified when this certificate was issued. Downloads are PEM files built in your browser.
        </DialogDescription>
        {attestation.isError ? <p className="text-danger">{errorMessage(attestation.error)}</p> : null}
        {!summary && !attestation.isError ? <p className="text-text-2">Loading the attestation.</p> : null}
        {summary ? (
          <>
            <div>
              {summary.present ? (
                <StatusBadge tone="ok">Verified</StatusBadge>
              ) : (
                <StatusBadge tone="neutral">Not attested</StatusBadge>
              )}
            </div>
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 font-mono text-[12px]">
              <dt className="text-text-3">ROOT</dt>
              <dd className="text-text">{summary.root || "—"}</dd>
              <dt className="text-text-3">FIRMWARE</dt>
              <dd className="text-text">{summary.firmware || "—"}</dd>
              <dt className="text-text-3">ATTESTED SERIAL</dt>
              <dd className="text-text">{summary.attestedSerial || "—"}</dd>
              <dt className="text-text-3">SLOT</dt>
              <dd className="text-text">{summary.slot || "—"}</dd>
              <dt className="text-text-3">PIN POLICY</dt>
              <dd className="text-text">{summary.pinPolicy || "—"}</dd>
              <dt className="text-text-3">TOUCH POLICY</dt>
              <dd className="text-text">{summary.touchPolicy || "—"}</dd>
            </dl>
            <div className="flex flex-wrap gap-2">
              <Button
                variant="outline"
                size="sm"
                disabled={!attestedPem}
                onClick={() => attestedPem && downloadText("attestation.pem", attestedPem)}
              >
                Download attestation
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={!intermediatePem}
                onClick={() => intermediatePem && downloadText("slot-f9.pem", intermediatePem)}
              >
                Download slot F9
              </Button>
            </div>
          </>
        ) : null}
        <div className="flex justify-end">
          <DialogClose asChild>
            <Button variant="outline">Close</Button>
          </DialogClose>
        </div>
      </DialogContent>
    </Dialog>
  );
}
