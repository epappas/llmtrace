"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Trash2 } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { DataTable, type Column } from "@/components/data-table";
import {
  type TraceEvent,
  type PaginatedResponse,
  listTraces,
  listTenants,
  findActiveTenant,
  deleteTrace,
} from "@/lib/api";

export default function TracesPage() {
  const router = useRouter();
  const [traces, setTraces] = useState<PaginatedResponse<TraceEvent> | null>(null);
  const [loading, setLoading] = useState(true);
  const [provider, setProvider] = useState("");
  const [model, setModel] = useState("");
  const [traceIdFilter, setTraceIdFilter] = useState("");
  const [dateFilter, setDateFilter] = useState("");
  const [limit] = useState(20);
  const [offset, setOffset] = useState(0);

  async function load() {
    setLoading(true);
    try {
      const tenantId = await findActiveTenant();

      const data = await listTraces({
        provider: provider || undefined,
        model: model || undefined,
        limit,
        offset,
      }, tenantId);
      
      // Apply client-side filtering for Trace ID and Date since the API might not support all filters yet
      let filteredData = data.data;
      if (traceIdFilter) {
        filteredData = filteredData.filter(t => t.trace_id.toLowerCase().includes(traceIdFilter.toLowerCase()));
      }
      if (dateFilter) {
        filteredData = filteredData.filter(t => t.created_at.startsWith(dateFilter));
      }

      setTraces({
        ...data,
        data: filteredData,
        total: traceIdFilter || dateFilter ? filteredData.length : data.total
      });
    } catch {
      setTraces(null);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
    
    // Auto-refresh every 30 seconds
    const interval = setInterval(load, 30000);
    return () => clearInterval(interval);
  }, [provider, model, limit, offset, traceIdFilter, dateFilter]);

  async function handleDeleteTrace(traceId: string, tenantId: string) {
    if (!confirm("Delete this trace permanently?")) return;
    try {
      // We will use the proxyMutate helper indirectly by calling a route
      // that we'll register in the Next.js API layer to talk to ClickHouse.
      const res = await fetch(`/api/proxy/traces/${traceId}?tenant=${tenantId}`, {
        method: "DELETE",
      });
      
      if (res.ok) {
        console.log(`[Traces] Trace ${traceId} deleted`);
        await load(); // Reload the list
      } else {
        throw new Error("Failed to delete trace");
      }
    } catch (e) {
      console.error("[Traces] Delete failed:", e);
      alert("Failed to delete trace.");
    }
  }

  const columns: Column<TraceEvent>[] = [
    {
      header: "Trace ID",
      accessor: (t: TraceEvent) => (
        <span className="font-mono text-xs">{t.trace_id.slice(0, 8)}…</span>
      ),
      sortKey: "trace_id",
    },
    {
      header: "Provider",
      accessor: (t: TraceEvent) => {
        const span = t.spans?.[0];
        return span ? <Badge variant="secondary">{span.provider}</Badge> : "—";
      },
      sortKey: (t: TraceEvent) => t.spans?.[0]?.provider ?? "",
    },
    {
      header: "Model",
      accessor: (t: TraceEvent) => t.spans?.[0]?.model_name ?? "—",
      sortKey: (t: TraceEvent) => t.spans?.[0]?.model_name ?? "",
    },
    {
      header: "Spans",
      accessor: (t: TraceEvent) => t.spans?.length ?? 0,
      sortKey: (t: TraceEvent) => t.spans?.length ?? 0,
    },
    {
      header: "Security",
      accessor: (t: TraceEvent) => {
        const maxScore = Math.max(0, ...(t.spans?.map((s) => s.security_score) ?? []));
        if (maxScore === 0) return <Badge variant="secondary">Clean</Badge>;
        return (
          <Badge variant={maxScore >= 70 ? "destructive" : "default"}>
            {maxScore}
          </Badge>
        );
      },
      sortKey: (t: TraceEvent) => Math.max(0, ...(t.spans?.map((s) => s.security_score) ?? [])),
    },
    {
      header: "Cost",
      accessor: (t: TraceEvent) => {
        const cost = t.spans?.reduce(
          (acc, s) => acc + (s.estimated_cost_usd ?? 0),
          0,
        );
        return cost ? `$${cost.toFixed(4)}` : "—";
      },
      sortKey: (t: TraceEvent) => t.spans?.reduce((acc, s) => acc + (s.estimated_cost_usd ?? 0), 0) ?? 0,
    },
    {
      header: "Created",
      accessor: (t: TraceEvent) =>
        new Date(t.created_at).toLocaleString(),
      sortKey: "created_at",
    },
    {
      header: "",
      accessor: (t: TraceEvent) => (
        <Button
          variant="ghost"
          size="icon"
          onClick={(e) => {
            e.stopPropagation();
            handleDeleteTrace(t.trace_id, t.tenant_id);
          }}
        >
          <Trash2 className="h-4 w-4 text-destructive" />
        </Button>
      ),
      className: "w-10",
    },
  ];

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold">Traces</h1>

      {/* Filters */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Filters</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-4">
            <div className="flex flex-col gap-1">
              <label className="text-xs font-medium text-muted-foreground">Provider</label>
              <input
                type="text"
                placeholder="Filter by Provider"
                value={provider}
                onChange={(e) => {
                  setProvider(e.target.value);
                  setOffset(0);
                }}
                className="rounded-md border bg-background px-3 py-2 text-sm"
              />
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-xs font-medium text-muted-foreground">Model</label>
              <input
                type="text"
                placeholder="Filter by Model"
                value={model}
                onChange={(e) => {
                  setModel(e.target.value);
                  setOffset(0);
                }}
                className="rounded-md border bg-background px-3 py-2 text-sm"
              />
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-xs font-medium text-muted-foreground">Trace ID</label>
              <input
                type="text"
                placeholder="Filter by Trace ID"
                value={traceIdFilter}
                onChange={(e) => {
                  setTraceIdFilter(e.target.value);
                  setOffset(0);
                }}
                className="rounded-md border bg-background px-3 py-2 text-sm font-mono"
              />
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-xs font-medium text-muted-foreground">Date (YYYY-MM-DD)</label>
              <input
                type="date"
                value={dateFilter}
                onChange={(e) => {
                  setDateFilter(e.target.value);
                  setOffset(0);
                }}
                className="rounded-md border bg-background px-3 py-2 text-sm"
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Table */}
      {loading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : (
        <>
          <DataTable
            columns={columns}
            data={traces?.data ?? []}
            onRowClick={(t) => router.push(`/traces/${t.trace_id}?tenant=${t.tenant_id}`)}
            emptyMessage="No traces found"
          />
          {/* Pagination */}
          {traces && (
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">
                Showing {offset + 1}–{Math.min(offset + limit, traces.total)} of{" "}
                {traces.total}
              </span>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={offset === 0}
                  onClick={() => setOffset(Math.max(0, offset - limit))}
                >
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={offset + limit >= traces.total}
                  onClick={() => setOffset(offset + limit)}
                >
                  Next
                </Button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
