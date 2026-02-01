"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { DataTable } from "@/components/data-table";
import type { TraceEvent, PaginatedResponse } from "@/lib/api";

export default function TracesPage() {
  const router = useRouter();
  const [traces, setTraces] = useState<PaginatedResponse<TraceEvent> | null>(null);
  const [loading, setLoading] = useState(true);
  const [provider, setProvider] = useState("");
  const [model, setModel] = useState("");
  const [limit] = useState(20);
  const [offset, setOffset] = useState(0);

  useEffect(() => {
    async function load() {
      setLoading(true);
      try {
        const params = new URLSearchParams();
        if (provider) params.set("provider", provider);
        if (model) params.set("model", model);
        params.set("limit", String(limit));
        params.set("offset", String(offset));
        const res = await fetch(`/api/proxy/traces?${params}`);
        const data = await res.json();
        setTraces(data);
      } catch {
        setTraces(null);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [provider, model, limit, offset]);

  const columns = [
    {
      header: "Trace ID",
      accessor: (t: TraceEvent) => (
        <span className="font-mono text-xs">{t.trace_id.slice(0, 8)}…</span>
      ),
    },
    {
      header: "Provider",
      accessor: (t: TraceEvent) => {
        const span = t.spans?.[0];
        return span ? <Badge variant="secondary">{span.provider}</Badge> : "—";
      },
    },
    {
      header: "Model",
      accessor: (t: TraceEvent) => t.spans?.[0]?.model_name ?? "—",
    },
    {
      header: "Spans",
      accessor: (t: TraceEvent) => t.spans?.length ?? 0,
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
    },
    {
      header: "Created",
      accessor: (t: TraceEvent) =>
        new Date(t.created_at).toLocaleString(),
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
            <input
              type="text"
              placeholder="Provider"
              value={provider}
              onChange={(e) => {
                setProvider(e.target.value);
                setOffset(0);
              }}
              className="rounded-md border bg-background px-3 py-2 text-sm"
            />
            <input
              type="text"
              placeholder="Model"
              value={model}
              onChange={(e) => {
                setModel(e.target.value);
                setOffset(0);
              }}
              className="rounded-md border bg-background px-3 py-2 text-sm"
            />
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
            onRowClick={(t) => router.push(`/traces/${t.trace_id}`)}
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
