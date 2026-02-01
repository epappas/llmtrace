"use client";

import { useEffect, useState } from "react";
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
import { Shield, AlertTriangle } from "lucide-react";
import { StatCard } from "@/components/stat-card";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { DataTable } from "@/components/data-table";
import type { TraceSpan, PaginatedResponse } from "@/lib/api";

const SEVERITY_COLORS: Record<string, string> = {
  Critical: "#dc2626",
  High: "#ea580c",
  Medium: "#ca8a04",
  Low: "#2563eb",
  Info: "#6b7280",
};

export default function SecurityPage() {
  const [findings, setFindings] = useState<PaginatedResponse<TraceSpan> | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const res = await fetch("/api/proxy/security/findings?limit=100");
        setFindings(await res.json());
      } catch {
        /* ignore */
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  // Aggregate severity counts
  const severityCounts: Record<string, number> = {};
  const findingTypes: Record<string, number> = {};
  if (findings?.data) {
    for (const span of findings.data) {
      for (const f of span.security_findings ?? []) {
        severityCounts[f.severity] = (severityCounts[f.severity] ?? 0) + 1;
        findingTypes[f.finding_type] = (findingTypes[f.finding_type] ?? 0) + 1;
      }
    }
  }

  const severityData = Object.entries(severityCounts).map(([name, value]) => ({
    name,
    value,
  }));

  const attackPatterns = Object.entries(findingTypes)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([name, count]) => ({ name, count }));

  const totalFindings = Object.values(severityCounts).reduce((a, b) => a + b, 0);
  const criticalCount = (severityCounts["Critical"] ?? 0) + (severityCounts["High"] ?? 0);

  const columns = [
    {
      header: "Model",
      accessor: (s: TraceSpan) => s.model_name,
    },
    {
      header: "Score",
      accessor: (s: TraceSpan) => (
        <Badge variant={s.security_score >= 70 ? "destructive" : "default"}>
          {s.security_score}
        </Badge>
      ),
    },
    {
      header: "Findings",
      accessor: (s: TraceSpan) =>
        s.security_findings?.map((f) => (
          <Badge key={f.id} variant="outline" className="mr-1">
            {f.severity}: {f.finding_type}
          </Badge>
        )),
    },
    {
      header: "Description",
      accessor: (s: TraceSpan) =>
        s.security_findings?.[0]?.description ?? "—",
      className: "max-w-md truncate",
    },
    {
      header: "Detected",
      accessor: (s: TraceSpan) =>
        new Date(s.started_at).toLocaleString(),
    },
  ];

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold">Security</h1>

      <div className="grid gap-4 md:grid-cols-3">
        <StatCard
          title="Total Findings"
          value={totalFindings}
          description="Across all spans"
          icon={Shield}
        />
        <StatCard
          title="Critical / High"
          value={criticalCount}
          description="Requires attention"
          icon={AlertTriangle}
        />
        <StatCard
          title="Affected Spans"
          value={findings?.total ?? 0}
          description="Spans with security_score > 0"
          icon={Shield}
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Severity Distribution</CardTitle>
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
                    {severityData.map((entry) => (
                      <Cell
                        key={entry.name}
                        fill={SEVERITY_COLORS[entry.name] ?? "#6b7280"}
                      />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-[260px] items-center justify-center text-sm text-muted-foreground">
                No findings
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Top Attack Patterns</CardTitle>
          </CardHeader>
          <CardContent>
            {attackPatterns.length > 0 ? (
              <ResponsiveContainer width="100%" height={260}>
                <BarChart data={attackPatterns} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                  <XAxis type="number" className="text-xs" />
                  <YAxis dataKey="name" type="category" width={150} className="text-xs" />
                  <Tooltip />
                  <Bar dataKey="count" fill="#ea580c" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-[260px] items-center justify-center text-sm text-muted-foreground">
                No findings
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Security Findings</CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : (
            <DataTable
              columns={columns}
              data={findings?.data ?? []}
              emptyMessage="No security findings — all clean!"
            />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
