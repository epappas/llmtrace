"use client";

import { useEffect, useState } from "react";
import { Activity, Shield, DollarSign, AlertTriangle } from "lucide-react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import { StatCard } from "@/components/stat-card";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import type {
  StorageStats,
  TraceSpan,
  PaginatedResponse,
} from "@/lib/api";

const SEVERITY_COLORS: Record<string, string> = {
  Critical: "#dc2626",
  High: "#ea580c",
  Medium: "#ca8a04",
  Low: "#2563eb",
  Info: "#6b7280",
};

const PIE_COLORS = ["#dc2626", "#ea580c", "#ca8a04", "#2563eb", "#6b7280"];

export default function OverviewPage() {
  const [stats, setStats] = useState<StorageStats | null>(null);
  const [findings, setFindings] = useState<PaginatedResponse<TraceSpan> | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      try {
        const [statsRes, findingsRes] = await Promise.all([
          fetch("/api/proxy/stats").then((r) => r.json()),
          fetch("/api/proxy/security/findings?limit=10").then((r) => r.json()),
        ]);
        setStats(statsRes);
        setFindings(findingsRes);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to load data");
      }
    }
    load();
  }, []);

  // Build severity breakdown from findings
  const severityCounts: Record<string, number> = {};
  if (findings?.data) {
    for (const span of findings.data) {
      for (const f of span.security_findings ?? []) {
        severityCounts[f.severity] = (severityCounts[f.severity] ?? 0) + 1;
      }
    }
  }
  const severityData = Object.entries(severityCounts).map(([name, value]) => ({
    name,
    value,
  }));

  // Mock time-series for the bar chart (in a real deployment, a dedicated
  // endpoint or aggregation query would provide this data).
  const traceActivity = [
    { hour: "00:00", traces: 12 },
    { hour: "04:00", traces: 8 },
    { hour: "08:00", traces: 34 },
    { hour: "12:00", traces: 52 },
    { hour: "16:00", traces: 47 },
    { hour: "20:00", traces: 29 },
  ];

  if (error) {
    return (
      <div className="space-y-6">
        <h1 className="text-3xl font-bold">Overview</h1>
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 text-muted-foreground">
            <AlertTriangle className="mb-2 h-8 w-8" />
            <p className="text-sm">Could not connect to the LLMTrace API</p>
            <p className="text-xs mt-1">{error}</p>
            <p className="text-xs mt-2">
              Ensure the proxy is running and{" "}
              <code className="bg-muted px-1 rounded">NEXT_PUBLIC_API_URL</code> is set.
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold">Overview</h1>

      {/* Stat cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title="Total Traces"
          value={stats?.total_traces ?? "—"}
          description="Across all tenants"
          icon={Activity}
        />
        <StatCard
          title="Total Spans"
          value={stats?.total_spans ?? "—"}
          description="Individual LLM calls"
          icon={Activity}
        />
        <StatCard
          title="Security Findings"
          value={findings?.total ?? "—"}
          description="Spans with findings"
          icon={Shield}
        />
        <StatCard
          title="Total Cost"
          value={
            stats?.total_cost_usd != null
              ? `$${stats.total_cost_usd.toFixed(2)}`
              : "—"
          }
          description="Estimated spend"
          icon={DollarSign}
        />
      </div>

      {/* Charts */}
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Trace Activity</CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={260}>
              <BarChart data={traceActivity}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                <XAxis dataKey="hour" className="text-xs" />
                <YAxis className="text-xs" />
                <Tooltip />
                <Bar dataKey="traces" fill="hsl(222.2 47.4% 11.2%)" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Security Severity Breakdown</CardTitle>
          </CardHeader>
          <CardContent>
            {severityData.length > 0 ? (
              <ResponsiveContainer width="100%" height={260}>
                <PieChart>
                  <Pie
                    data={severityData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    outerRadius={90}
                    label={({ name, value }) => `${name}: ${value}`}
                  >
                    {severityData.map((entry, i) => (
                      <Cell
                        key={entry.name}
                        fill={SEVERITY_COLORS[entry.name] ?? PIE_COLORS[i % PIE_COLORS.length]}
                      />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-[260px] items-center justify-center text-sm text-muted-foreground">
                No security findings detected
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Recent findings */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Recent Security Findings</CardTitle>
        </CardHeader>
        <CardContent>
          {findings?.data && findings.data.length > 0 ? (
            <div className="space-y-3">
              {findings.data.slice(0, 5).map((span) => (
                <div
                  key={span.span_id}
                  className="flex items-center justify-between rounded-md border p-3"
                >
                  <div className="space-y-1">
                    <p className="text-sm font-medium">{span.model_name}</p>
                    <p className="text-xs text-muted-foreground">
                      {span.security_findings?.[0]?.description ?? "Security finding"}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge
                      variant={
                        span.security_score >= 70
                          ? "destructive"
                          : span.security_score >= 40
                            ? "default"
                            : "secondary"
                      }
                    >
                      Score: {span.security_score}
                    </Badge>
                    {span.security_findings?.[0] && (
                      <Badge variant="outline">
                        {span.security_findings[0].severity}
                      </Badge>
                    )}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No recent findings</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
