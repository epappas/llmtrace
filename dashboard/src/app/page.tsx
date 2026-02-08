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
import {
  type StorageStats,
  type TraceSpan,
  type TraceEvent,
  type PaginatedResponse,
  getStats,
  listSecurityFindings,
  listTenants,
  listTraces,
  findActiveTenant,
  getGlobalStats,
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
  const [globalStats, setGlobalStats] = useState<StorageStats | null>(null);
  const [findings, setFindings] = useState<PaginatedResponse<TraceSpan> | null>(null);
  const [activityData, setActivityData] = useState<{ hour: string; traces: number }[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      try {
        // Find the tenant with the most activity to display meaningful data
        const tenantId = await findActiveTenant();

        const [statsRes, findingsRes, tracesRes, globalRes] = await Promise.all([
          getStats(tenantId),
          listSecurityFindings({ limit: 10 }, tenantId),
          listTraces({ limit: 100 }, tenantId),
          getGlobalStats(),
        ]);
        setStats(statsRes);
        setGlobalStats(globalRes);
        setFindings(findingsRes);

        // Aggregate trace activity (last 24h)
        const now = new Date();
        const buckets = new Map<string, number>();
        
        // Initialize buckets for the last 6 hours (example)
        for (let i = 5; i >= 0; i--) {
          const d = new Date(now.getTime() - i * 60 * 60 * 1000);
          const key = `${d.getHours().toString().padStart(2, '0')}:00`;
          buckets.set(key, 0);
        }

        if (tracesRes?.data) {
          for (const trace of tracesRes.data) {
            const date = new Date(trace.created_at);
            const key = `${date.getHours().toString().padStart(2, '0')}:00`;
            if (buckets.has(key)) {
              buckets.set(key, (buckets.get(key) ?? 0) + 1);
            }
          }
        }

        const aggregated = Array.from(buckets.entries()).map(([hour, traces]) => ({
          hour,
          traces,
        }));
        setActivityData(aggregated);

      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to load data");
      }
    }
    load();
    
    // Auto-refresh every 30 seconds
    const interval = setInterval(load, 30000);
    return () => clearInterval(interval);
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
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
        <StatCard
          title="Global Transactions"
          value={globalStats?.total_traces ?? "—"}
          description="Total across all tenants"
          icon={Activity}
        />
        <StatCard
          title="Total Traces"
          value={stats?.total_traces ?? "—"}
          description="Selected tenant traces"
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
              <BarChart data={activityData}>
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
