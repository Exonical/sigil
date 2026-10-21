import { useQuery } from "@tanstack/react-query";

import { useApi, errorMessage } from "@/api/client";
import { Card } from "@/components/ui/card";
import { PageHeader } from "@/app/Layout";

export function Dashboard() {
  const api = useApi();
  const dashboard = useQuery({
    queryKey: ["dashboard"],
    queryFn: () => api.getDashboard({}),
  });

  if (dashboard.isError) return <p className="text-destructive">{errorMessage(dashboard.error)}</p>;
  if (!dashboard.data) return <p className="text-muted-foreground">Loading the dashboard.</p>;
  const data = dashboard.data;

  return (
    <>
      <PageHeader title="Dashboard" />
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
        <Card title="Active certificates" value={data.activeCertificates} />
        <Card title="Expiring in 30 days" value={data.certificatesExpiring30Days} />
        <Card title="Lost tokens pending revocation" value={data.lostTokensPendingRevocation} />
        <Card title="Tokens by status" lines={Object.entries(data.tokensByStatus)} />
        <Card title="Stations by status" lines={Object.entries(data.stationsByStatus)} />
      </div>
    </>
  );
}
