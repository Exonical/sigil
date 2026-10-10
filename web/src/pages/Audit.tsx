import { useMutation, useQuery } from "@tanstack/react-query";
import * as React from "react";

import { useAuth } from "@/auth/AuthProvider";
import { isAdmin } from "@/auth/roles";
import { errorMessage, useApi } from "@/api/client";
import { PageHeader } from "@/app/Layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { StatusBadge } from "@/components/ui/status";
import { statusTone } from "@/lib/status";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useToast } from "@/components/ui/toast";
import { formatUnix, fromDateInput } from "@/lib/format";

const PAGE_SIZE = 50;

interface Filters {
  actorType: string;
  actorId: string;
  action: string;
  target: string;
  from: string;
  to: string;
}

const EMPTY: Filters = { actorType: "", actorId: "", action: "", target: "", from: "", to: "" };

export function Audit() {
  const api = useApi();
  const auth = useAuth();
  const toast = useToast();
  const admin = isAdmin(auth.roles);
  const [filters, setFilters] = React.useState<Filters>(EMPTY);
  // Cursors are the sequence numbers that opened each page. Page 0 uses cursor 0 (the newest events).
  const [cursors, setCursors] = React.useState<bigint[]>([0n]);
  const cursor = cursors[cursors.length - 1] ?? 0n;

  const query = useQuery({
    queryKey: ["audit", filters, String(cursor)],
    queryFn: () =>
      api.listAudit({
        actorType: filters.actorType,
        actorId: filters.actorId,
        action: filters.action,
        target: filters.target,
        fromUnix: fromDateInput(filters.from),
        toUnix: fromDateInput(filters.to),
        beforeSeq: cursor,
        pageSize: PAGE_SIZE,
      }),
  });

  const verify = useMutation({
    mutationFn: () => api.verifyAudit({}),
    onSuccess: (result) =>
      toast.notify(
        result.ok
          ? { title: "Audit chain verified", description: `${String(result.eventsChecked)} events checked.` }
          : { title: "Audit chain verification failed", description: result.failure, tone: "error" },
      ),
    onError: (error) => toast.notify({ title: "Could not verify the chain", description: errorMessage(error), tone: "error" }),
  });

  const setFilter = (key: keyof Filters, value: string) => {
    setFilters({ ...filters, [key]: value });
    setCursors([0n]);
  };

  const nextCursor = query.data?.nextBeforeSeq ?? 0n;

  return (
    <>
      <PageHeader title="Audit">
        {admin ? (
          <Button variant="outline" disabled={verify.isPending} onClick={() => verify.mutate()}>
            Verify chain
          </Button>
        ) : null}
      </PageHeader>
      <div className="mb-4 grid gap-2 sm:grid-cols-3 xl:grid-cols-6">
        {(["actorType", "actorId", "action", "target"] as const).map((key) => (
          <Input
            key={key}
            aria-label={`Filter ${key}`}
            placeholder={key}
            value={filters[key]}
            onChange={(event) => setFilter(key, event.target.value)}
          />
        ))}
        <Input aria-label="From date" type="date" value={filters.from} onChange={(event) => setFilter("from", event.target.value)} />
        <Input aria-label="To date" type="date" value={filters.to} onChange={(event) => setFilter("to", event.target.value)} />
      </div>
      {query.isError ? <p className="text-destructive">{errorMessage(query.error)}</p> : null}
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Seq</TableHead>
            <TableHead>When</TableHead>
            <TableHead>Actor</TableHead>
            <TableHead>Action</TableHead>
            <TableHead>Target</TableHead>
            <TableHead>Outcome</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {(query.data?.events ?? []).map((event) => (
            <TableRow key={String(event.seq)}>
              <TableCell className="font-mono text-[12px] tabular-nums">{String(event.seq)}</TableCell>
              <TableCell className="font-mono text-[12px] tabular-nums">{formatUnix(event.occurredAtUnix)}</TableCell>
              <TableCell className="font-mono text-[12px]">
                {event.actorType}:{event.actorId}
              </TableCell>
              <TableCell>{event.action}</TableCell>
              <TableCell className="font-mono text-[12px]">
                {event.targetType} {event.targetId}
              </TableCell>
              <TableCell><StatusBadge tone={statusTone(event.outcome)}>{event.outcome}</StatusBadge></TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      <div className="mt-4 flex justify-end gap-2">
        <Button variant="outline" size="sm" disabled={cursors.length === 1} onClick={() => setCursors(cursors.slice(0, -1))}>
          Newer
        </Button>
        <Button
          variant="outline"
          size="sm"
          disabled={nextCursor === 0n}
          onClick={() => setCursors([...cursors, nextCursor])}
        >
          Older
        </Button>
      </div>
    </>
  );
}
