import { keepPreviousData, useQuery } from "@tanstack/react-query";
import * as React from "react";
import { Link } from "react-router";

import { errorMessage, useApi } from "@/api/client";
import { StatusBadge } from "@/components/ui/status";
import { statusTone } from "@/lib/status";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/app/Layout";
import { pageCount } from "@/lib/format";

const PAGE_SIZE = 25;
const STATUSES = ["", "active", "unassigned", "lost", "retired"] as const;

export function Tokens() {
  const api = useApi();
  const [search, setSearch] = React.useState("");
  const [status, setStatus] = React.useState<(typeof STATUSES)[number]>("");
  const [page, setPage] = React.useState(0);

  const query = useQuery({
    queryKey: ["tokens", search, status, page],
    queryFn: () => api.listTokens({ search, status, pageSize: PAGE_SIZE, page }),
    placeholderData: keepPreviousData,
  });

  return (
    <>
      <PageHeader title="Tokens" />
      <div className="mb-4 flex flex-wrap gap-2">
        <Input
          aria-label="Search tokens"
          placeholder="Serial, nickname, user or email"
          className="max-w-xs"
          value={search}
          onChange={(event) => {
            setSearch(event.target.value);
            setPage(0);
          }}
        />
        <select
          aria-label="Status"
          className="h-9 rounded-md border border-input bg-card px-2 text-sm"
          value={status}
          onChange={(event) => {
            setStatus(event.target.value as (typeof STATUSES)[number]);
            setPage(0);
          }}
        >
          {STATUSES.map((value) => (
            <option key={value || "all"} value={value}>
              {value || "All statuses"}
            </option>
          ))}
        </select>
      </div>
      {query.isError ? <p className="text-destructive">{errorMessage(query.error)}</p> : null}
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Serial</TableHead>
            <TableHead>Model</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Assigned to</TableHead>
            <TableHead>Certificates</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {(query.data?.tokens ?? []).map((token) => (
            <TableRow key={token.serial}>
              <TableCell>
                <Link className="font-mono underline" to={`/tokens/${encodeURIComponent(token.serial)}`}>
                  {token.serial}
                </Link>
                {token.nickname ? <span className="ml-2 text-muted-foreground">{token.nickname}</span> : null}
              </TableCell>
              <TableCell>{token.model}</TableCell>
              <TableCell>
                <StatusBadge tone={statusTone(token.status)}>{token.status}</StatusBadge>
              </TableCell>
              <TableCell>{token.assignedUser?.username || token.assignedUser?.email || "—"}</TableCell>
              <TableCell className="font-mono text-[12px] tabular-nums">{String(token.activeCertificates)}</TableCell>
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
    </>
  );
}
