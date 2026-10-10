import { keepPreviousData, useQuery } from "@tanstack/react-query";
import * as React from "react";

import { errorMessage, useApi } from "@/api/client";
import { PageHeader } from "@/app/Layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { pageCount } from "@/lib/format";

const PAGE_SIZE = 25;

export function Users() {
  const api = useApi();
  const [search, setSearch] = React.useState("");
  const [page, setPage] = React.useState(0);
  const query = useQuery({
    queryKey: ["users", search, page],
    queryFn: () => api.listUsers({ search, pageSize: PAGE_SIZE, page }),
    placeholderData: keepPreviousData,
  });

  return (
    <>
      <PageHeader title="Users" />
      <Input
        aria-label="Search users"
        placeholder="Username, email or name"
        className="mb-4 max-w-xs"
        value={search}
        onChange={(event) => {
          setSearch(event.target.value);
          setPage(0);
        }}
      />
      {query.isError ? <p className="text-destructive">{errorMessage(query.error)}</p> : null}
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Username</TableHead>
            <TableHead>Email</TableHead>
            <TableHead>Name</TableHead>
            <TableHead>Tokens</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {(query.data?.users ?? []).map((entry) => (
            <TableRow key={entry.user?.id}>
              <TableCell>{entry.user?.username}</TableCell>
              <TableCell>{entry.user?.email}</TableCell>
              <TableCell>{entry.user?.displayName}</TableCell>
              <TableCell>{String(entry.tokenCount)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      <div className="mt-4 flex items-center justify-between text-sm">
        <span className="text-muted-foreground">Page {page + 1} of {pageCount(query.data?.total ?? 0n, PAGE_SIZE)}</span>
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
