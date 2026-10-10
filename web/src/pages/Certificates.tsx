import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as React from "react";
import { Link } from "react-router";

import { useAuth } from "@/auth/AuthProvider";
import { isAdmin } from "@/auth/roles";
import { errorMessage, useApi } from "@/api/client";
import { PageHeader } from "@/app/Layout";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useToast } from "@/components/ui/toast";
import { formatUnix, fromDateInput, pageCount } from "@/lib/format";

const PAGE_SIZE = 25;
const REASONS = ["keyCompromise", "cessationOfOperation", "superseded", "unspecified"] as const;

export function Certificates() {
  const api = useApi();
  const auth = useAuth();
  const toast = useToast();
  const queryClient = useQueryClient();
  const admin = isAdmin(auth.roles);
  const [status, setStatus] = React.useState("active");
  const [profile, setProfile] = React.useState("");
  const [tokenSerial, setTokenSerial] = React.useState("");
  const [expiringBefore, setExpiringBefore] = React.useState("");
  const [page, setPage] = React.useState(0);
  const [revoking, setRevoking] = React.useState<string | null>(null);
  const [reason, setReason] = React.useState<(typeof REASONS)[number]>("keyCompromise");

  const query = useQuery({
    queryKey: ["certificates", status, profile, tokenSerial, expiringBefore, page],
    queryFn: () =>
      api.listCertificates({
        status,
        profile,
        tokenSerial,
        expiringBeforeUnix: fromDateInput(expiringBefore),
        pageSize: PAGE_SIZE,
        page,
      }),
    placeholderData: keepPreviousData,
  });

  const revoke = useMutation({
    mutationFn: (id: string) => api.revokeCertificate({ certificateId: id, reason }),
    onSuccess: () => {
      setRevoking(null);
      void queryClient.invalidateQueries({ queryKey: ["certificates"] });
      toast.notify({ title: "Certificate revoked" });
    },
    onError: (error) => toast.notify({ title: "Could not revoke", description: errorMessage(error), tone: "error" }),
  });

  return (
    <>
      <PageHeader title="Certificates" />
      <div className="mb-4 flex flex-wrap gap-2">
        <select
          aria-label="Certificate status"
          className="h-9 rounded-md border border-input bg-card px-2 text-sm"
          value={status}
          onChange={(event) => {
            setStatus(event.target.value);
            setPage(0);
          }}
        >
          <option value="">All statuses</option>
          <option value="active">Active</option>
          <option value="superseded">Superseded</option>
          <option value="revoked">Revoked</option>
        </select>
        <Input
          aria-label="Profile"
          placeholder="Profile"
          className="max-w-44"
          value={profile}
          onChange={(event) => {
            setProfile(event.target.value);
            setPage(0);
          }}
        />
        <Input
          aria-label="Token serial"
          placeholder="Token serial"
          className="max-w-44"
          value={tokenSerial}
          onChange={(event) => {
            setTokenSerial(event.target.value);
            setPage(0);
          }}
        />
        <Input
          aria-label="Expiring before"
          type="date"
          className="max-w-44"
          value={expiringBefore}
          onChange={(event) => {
            setExpiringBefore(event.target.value);
            setPage(0);
          }}
        />
      </div>
      {query.isError ? <p className="text-destructive">{errorMessage(query.error)}</p> : null}
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Token</TableHead>
            <TableHead>Slot</TableHead>
            <TableHead>Subject</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Expires</TableHead>
            {admin ? <TableHead aria-label="Actions" /> : null}
          </TableRow>
        </TableHeader>
        <TableBody>
          {(query.data?.certificates ?? []).map((certificate) => (
            <TableRow key={certificate.id}>
              <TableCell>
                <Link className="underline" to={`/tokens/${encodeURIComponent(certificate.tokenSerial)}`}>
                  {certificate.tokenSerial}
                </Link>
              </TableCell>
              <TableCell>{certificate.slot}</TableCell>
              <TableCell>{certificate.subject}</TableCell>
              <TableCell>
                <Badge>{certificate.status}</Badge>
              </TableCell>
              <TableCell>{formatUnix(certificate.notAfterUnix)}</TableCell>
              {admin ? (
                <TableCell>
                  {certificate.status !== "revoked" ? (
                    <Button variant="outline" size="sm" onClick={() => setRevoking(certificate.id)}>
                      Revoke
                    </Button>
                  ) : null}
                </TableCell>
              ) : null}
            </TableRow>
          ))}
        </TableBody>
      </Table>
      <div className="mt-4 flex items-center justify-between text-sm">
        <span className="text-muted-foreground">
          Page {page + 1} of {pageCount(query.data?.total ?? 0n, PAGE_SIZE)}
        </span>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" disabled={page === 0} onClick={() => setPage(page - 1)}>
            Previous
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={(page + 1) * PAGE_SIZE >= Number(query.data?.total ?? 0)}
            onClick={() => setPage(page + 1)}
          >
            Next
          </Button>
        </div>
      </div>

      {admin ? (
        <Dialog open={revoking !== null} onOpenChange={(open) => !open && setRevoking(null)}>
          <DialogContent>
            <DialogTitle>Revoke certificate</DialogTitle>
            <DialogDescription>The certificate authority revokes it, and the token can no longer use it.</DialogDescription>
            <label className="grid gap-1 text-sm">
              Reason
              <select
                className="h-9 rounded-md border border-input bg-card px-2"
                value={reason}
                onChange={(event) => setReason(event.target.value as (typeof REASONS)[number])}
              >
                {REASONS.map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </select>
            </label>
            <div className="flex justify-end gap-2">
              <DialogClose asChild>
                <Button variant="outline">Cancel</Button>
              </DialogClose>
              <Button variant="destructive" disabled={revoke.isPending} onClick={() => revoking && revoke.mutate(revoking)}>
                Revoke
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      ) : null}
    </>
  );
}
