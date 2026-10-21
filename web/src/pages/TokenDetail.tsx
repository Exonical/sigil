import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as React from "react";
import { useParams } from "react-router";

import { useAuth } from "@/auth/AuthProvider";
import { isAdmin } from "@/auth/roles";
import { errorMessage, useApi } from "@/api/client";
import { PageHeader } from "@/app/Layout";
import { StatusBadge } from "@/components/ui/status";
import { statusTone } from "@/lib/status";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useToast } from "@/components/ui/toast";
import { formatUnix } from "@/lib/format";

import { AttestationDialog } from "./AttestationDialog";

const VENDOR = "Yubico";

export function TokenDetail() {
  const { serial = "" } = useParams();
  const api = useApi();
  const auth = useAuth();
  const toast = useToast();
  const queryClient = useQueryClient();
  const admin = isAdmin(auth.roles);
  const [username, setUsername] = React.useState("");
  const [nickname, setNickname] = React.useState("");
  const [deleteOpen, setDeleteOpen] = React.useState(false);
  const [confirmSerial, setConfirmSerial] = React.useState("");
  const [attestingId, setAttestingId] = React.useState<string | null>(null);

  const detail = useQuery({
    queryKey: ["token", serial],
    queryFn: () => api.getToken({ vendor: VENDOR, serial }),
    enabled: serial !== "",
  });

  const ref = { vendor: VENDOR, serial };
  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ["token", serial] });
    void queryClient.invalidateQueries({ queryKey: ["tokens"] });
  };
  const run = useMutation({
    mutationFn: async (action: () => Promise<unknown>) => action(),
    onSuccess: () => {
      refresh();
      toast.notify({ title: "Saved" });
    },
    onError: (error) => toast.notify({ title: "Could not complete the change", description: errorMessage(error), tone: "error" }),
  });

  if (detail.isError) return <p className="text-destructive">{errorMessage(detail.error)}</p>;
  if (!detail.data?.token) return <p className="text-muted-foreground">Loading the token.</p>;
  const { token, certificates, escrow, audit } = detail.data;
  const lost = token.status === "lost";

  return (
    <>
      <PageHeader title={`Token ${token.serial}`}>
        <div className="flex items-center gap-2">
          <StatusBadge tone={statusTone(token.status)}>{token.status}</StatusBadge>
          {token.nickname ? <span className="text-muted-foreground">{token.nickname}</span> : null}
        </div>
      </PageHeader>

      <section className="mb-6 grid gap-2 text-sm sm:grid-cols-2">
        <p>
          <span className="text-muted-foreground">Model: </span>
          {token.model}
        </p>
        <p>
          <span className="text-muted-foreground">Assigned to: </span>
          {token.assignedUser?.username || token.assignedUser?.email || "Nobody"}
        </p>
        <p>
          <span className="text-muted-foreground">Last seen: </span>
          {formatUnix(token.lastSeenUnix)}
        </p>
        {lost ? (
          <p>
            <span className="text-muted-foreground">Reported lost: </span>
            {formatUnix(token.lostAtUnix)}
          </p>
        ) : null}
      </section>

      <section className="mb-6 space-y-3">
        <h2 className="sg-label mb-2 text-text-2">Actions</h2>
        <div className="flex flex-wrap items-end gap-2">
          <Input
            aria-label="Username or email to assign"
            placeholder="Username or email"
            className="max-w-xs"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
          />
          <Button
            variant="outline"
            disabled={username.trim() === "" || run.isPending}
            onClick={() => run.mutate(() => api.assignToken({ token: ref, usernameOrEmail: username.trim() }))}
          >
            Assign
          </Button>
          <Button variant="outline" disabled={run.isPending} onClick={() => run.mutate(() => api.unassignToken(ref))}>
            Unassign
          </Button>
        </div>
        <div className="flex flex-wrap items-end gap-2">
          <Input
            aria-label="Nickname"
            placeholder="Nickname"
            className="max-w-xs"
            value={nickname}
            onChange={(event) => setNickname(event.target.value)}
          />
          <Button
            variant="outline"
            disabled={run.isPending}
            onClick={() => run.mutate(() => api.setNickname({ token: ref, nickname: nickname.trim() }))}
          >
            Save nickname
          </Button>
        </div>
        <div className="flex flex-wrap gap-2">
          {lost ? (
            <Button
              variant="outline"
              disabled={run.isPending}
              onClick={() =>
                run.mutate(async () => {
                  const response = await api.markFound(ref);
                  if (response.reEnrollmentRequired) {
                    toast.notify({
                      title: "Re-enrollment required",
                      description: "A certificate on this token was already revoked. The user must enroll again.",
                    });
                  }
                })
              }
            >
              Mark found
            </Button>
          ) : (
            <Button variant="outline" disabled={run.isPending} onClick={() => run.mutate(() => api.reportLost(ref))}>
              Report lost
            </Button>
          )}
          {admin ? (
            <Button variant="destructive" onClick={() => setDeleteOpen(true)}>
              Delete key
            </Button>
          ) : null}
        </div>
      </section>

      <section className="mb-6">
        <h2 className="sg-label mb-2 text-text-2">Certificates</h2>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Slot</TableHead>
              <TableHead>Profile</TableHead>
              <TableHead>Subject</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Attestation</TableHead>
              <TableHead>Expires</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {certificates.map((certificate) => (
              <TableRow key={certificate.id}>
                <TableCell className="font-mono text-[12px] tabular-nums">{certificate.slot}</TableCell>
                <TableCell>{certificate.profile}</TableCell>
                <TableCell>{certificate.subject}</TableCell>
                <TableCell><StatusBadge tone={statusTone(certificate.status)}>{certificate.status}</StatusBadge></TableCell>
                <TableCell>
                  {certificate.attestation?.present ? (
                    <button
                      type="button"
                      className="flex items-center gap-2 text-left"
                      onClick={() => setAttestingId(certificate.id)}
                    >
                      <StatusBadge tone="ok">Verified</StatusBadge>
                      <span className="font-mono text-[12px] text-text-2">{certificate.attestation.root}</span>
                    </button>
                  ) : (
                    <span className="text-text-3">—</span>
                  )}
                </TableCell>
                <TableCell className="font-mono text-[12px] tabular-nums">{formatUnix(certificate.notAfterUnix)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        <AttestationDialog
          certificateId={attestingId}
          open={attestingId !== null}
          onOpenChange={(open) => {
            if (!open) setAttestingId(null);
          }}
        />
      </section>

      <section className="mb-6">
        <h2 className="sg-label mb-2 text-text-2">Escrow</h2>
        <p className="mb-2 text-xs text-muted-foreground">Metadata only. Escrowed values are never shown.</p>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Kind</TableHead>
              <TableHead>Version</TableHead>
              <TableHead>State</TableHead>
              <TableHead>Created</TableHead>
              <TableHead>Activated</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {escrow.map((version) => (
              <TableRow key={`${version.kind}-${version.version}`}>
                <TableCell>{version.kind}</TableCell>
                <TableCell className="font-mono text-[12px] tabular-nums">{String(version.version)}</TableCell>
                <TableCell><StatusBadge tone={statusTone(version.state)}>{version.state}</StatusBadge></TableCell>
                <TableCell className="font-mono text-[12px] tabular-nums">{formatUnix(version.createdAtUnix)}</TableCell>
                <TableCell className="font-mono text-[12px] tabular-nums">{formatUnix(version.activatedAtUnix)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </section>

      <section className="mb-6">
        <h2 className="sg-label mb-2 text-text-2">Recent audit</h2>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>When</TableHead>
              <TableHead>Actor</TableHead>
              <TableHead>Action</TableHead>
              <TableHead>Outcome</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {audit.map((event) => (
              <TableRow key={String(event.seq)}>
                <TableCell className="font-mono text-[12px] tabular-nums">{formatUnix(event.occurredAtUnix ?? event.occurredAtUnix)}</TableCell>
                <TableCell>{event.actorId}</TableCell>
                <TableCell>{event.action}</TableCell>
                <TableCell><StatusBadge tone={statusTone(event.outcome)}>{event.outcome}</StatusBadge></TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </section>

      {admin ? (
        <Dialog open={deleteOpen} onOpenChange={setDeleteOpen}>
          <DialogContent>
            <DialogTitle>Delete key {token.serial}</DialogTitle>
            <DialogDescription>
              This revokes every active certificate for this token at the certificate authority and retires the token.
              Type the serial number to confirm.
            </DialogDescription>
            <Input
              aria-label="Type the serial to confirm"
              value={confirmSerial}
              onChange={(event) => setConfirmSerial(event.target.value)}
            />
            <div className="flex justify-end gap-2">
              <DialogClose asChild>
                <Button variant="outline">Cancel</Button>
              </DialogClose>
              <Button
                variant="destructive"
                disabled={confirmSerial !== token.serial || run.isPending}
                onClick={() => {
                  run.mutate(() => api.deleteKey({ token: ref, confirmSerial }));
                  setDeleteOpen(false);
                  setConfirmSerial("");
                }}
              >
                Delete key
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      ) : null}
    </>
  );
}
