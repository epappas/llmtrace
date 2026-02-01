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
} from "recharts";
import { DollarSign, TrendingUp, AlertTriangle } from "lucide-react";
import { StatCard } from "@/components/stat-card";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { SpendSnapshot, StorageStats, WindowSpend } from "@/lib/api";

export default function CostsPage() {
  const [costs, setCosts] = useState<SpendSnapshot | null>(null);
  const [stats, setStats] = useState<StorageStats | null>(null);
  const [costsError, setCostsError] = useState(false);

  useEffect(() => {
    async function load() {
      try {
        const statsRes = await fetch("/api/proxy/stats");
        setStats(await statsRes.json());
      } catch {
        /* ignore */
      }
      try {
        const costsRes = await fetch("/api/proxy/costs/current");
        if (costsRes.ok) {
          setCosts(await costsRes.json());
        } else {
          setCostsError(true);
        }
      } catch {
        setCostsError(true);
      }
    }
    load();
  }, []);

  const budgetData = costs?.windows?.map((w: WindowSpend) => ({
    name: w.window,
    spent: w.current_spend_usd,
    limit: w.hard_limit_usd,
    remaining: Math.max(0, w.hard_limit_usd - w.current_spend_usd),
  })) ?? [];

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold">Costs</h1>

      <div className="grid gap-4 md:grid-cols-3">
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
        <StatCard
          title="Total Spans"
          value={stats?.total_spans ?? "—"}
          description="Billable LLM calls"
          icon={TrendingUp}
        />
        <StatCard
          title="Budget Status"
          value={
            costs?.windows?.[0]
              ? `${costs.windows[0].utilization_pct.toFixed(1)}%`
              : "—"
          }
          description={
            costs?.windows?.[0]
              ? `${costs.windows[0].window} budget`
              : "Cost caps not enabled"
          }
          icon={AlertTriangle}
        />
      </div>

      {/* Budget windows */}
      {costs && costs.windows?.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Budget Windows</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {costs.windows.map((w) => (
                <div key={w.window} className="space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <span className="font-medium capitalize">{w.window}</span>
                    <span className="text-muted-foreground">
                      ${w.current_spend_usd.toFixed(4)} / ${w.hard_limit_usd.toFixed(2)}
                    </span>
                  </div>
                  <div className="h-3 w-full rounded-full bg-muted">
                    <div
                      className={`h-3 rounded-full transition-all ${
                        w.utilization_pct >= 80
                          ? "bg-destructive"
                          : w.utilization_pct >= 50
                            ? "bg-yellow-500"
                            : "bg-primary"
                      }`}
                      style={{ width: `${Math.min(100, w.utilization_pct)}%` }}
                    />
                  </div>
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <span>{w.utilization_pct.toFixed(1)}% used</span>
                    {w.soft_limit_usd && (
                      <Badge variant="outline" className="text-xs">
                        Soft: ${w.soft_limit_usd.toFixed(2)}
                      </Badge>
                    )}
                    <span className="ml-auto">
                      Resets in {formatDuration(w.resets_in_secs)}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Budget chart */}
      {budgetData.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Budget Utilization</CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={budgetData}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                <XAxis dataKey="name" className="text-xs" />
                <YAxis className="text-xs" />
                <Tooltip formatter={(value: number) => `$${value.toFixed(4)}`} />
                <Bar dataKey="spent" name="Spent" fill="#ea580c" radius={[4, 4, 0, 0]} />
                <Bar
                  dataKey="remaining"
                  name="Remaining"
                  fill="hsl(210 40% 96.1%)"
                  radius={[4, 4, 0, 0]}
                />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      )}

      {costsError && (
        <Card>
          <CardContent className="py-8 text-center text-sm text-muted-foreground">
            <AlertTriangle className="mx-auto mb-2 h-6 w-6" />
            <p>Cost caps are not enabled in the proxy configuration.</p>
            <p className="mt-1 text-xs">
              Enable <code className="bg-muted px-1 rounded">cost_caps.enabled: true</code>{" "}
              in config.yaml.
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  return `${Math.round(seconds / 3600)}h ${Math.round((seconds % 3600) / 60)}m`;
}
