import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as React from "react";

import { useAuth } from "@/auth/AuthProvider";
import { isAdmin } from "@/auth/roles";
import { errorMessage, useApi } from "@/api/client";
import { PageHeader } from "@/app/Layout";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useToast } from "@/components/ui/toast";

export function Stations() {
  const api = useApi();
  const auth = useAuth();
  const toast = useToast();
  const queryClient = useQueryClient();
  const admin = isAdmin(auth.roles);
  const [dnsName, setDnsName] = React.useState("");
  const [mode, setMode] = React.useState<"station" | "user">("station");

  const query = useQuery({ queryKey: ["stations"], queryFn: () => api.listStations({}) });
  const change = useMutation({
    mutationFn: (action: () => Promise<unknown>) => action(),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["stations"] });
      toast.notify({ title: "Station updated" });
    },
    onError: (error) => toast.notify({ title: "Could not update the station", description: errorMessage(error), tone: "error" }),
  });

  return (
    <>
      <PageHeader title="Stations" />
      {admin ? (
        <form
          className="mb-4 flex flex-wrap items-end gap-2"
          onSubmit={(event) => {
            event.preventDefault();
            change.mutate(async () => {
              await api.addStation({ dnsName: dnsName.trim(), mode });
              setDnsName("");
            });
          }}
        >
          <Input
            aria-label="Station DNS name"
            placeholder="station.example.test"
            className="max-w-xs"
            value={dnsName}
            onChange={(event) => setDnsName(event.target.value)}
          />
          <select
            aria-label="Station mode"
            className="h-9 rounded-md border border-input bg-card px-2 text-sm"
            value={mode}
            onChange={(event) => setMode(event.target.value as "station" | "user")}
          >
            <option value="station">station</option>
            <option value="user">user</option>
          </select>
          <Button type="submit" disabled={dnsName.trim() === "" || change.isPending}>
            Add station
          </Button>
        </form>
      ) : null}
      {query.isError ? <p className="text-destructive">{errorMessage(query.error)}</p> : null}
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>DNS name</TableHead>
            <TableHead>Mode</TableHead>
            <TableHead>Status</TableHead>
            {admin ? <TableHead aria-label="Actions" /> : null}
          </TableRow>
        </TableHeader>
        <TableBody>
          {(query.data?.stations ?? []).map((station) => (
            <TableRow key={station.id}>
              <TableCell>{station.dnsName}</TableCell>
              <TableCell>{station.mode}</TableCell>
              <TableCell>
                <Badge>{station.status}</Badge>
              </TableCell>
              {admin ? (
                <TableCell>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={change.isPending}
                    onClick={() =>
                      change.mutate(() =>
                        api.setStationStatus({
                          id: station.id,
                          status: station.status === "active" ? "disabled" : "active",
                        }),
                      )
                    }
                  >
                    {station.status === "active" ? "Disable" : "Enable"}
                  </Button>
                </TableCell>
              ) : null}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </>
  );
}
