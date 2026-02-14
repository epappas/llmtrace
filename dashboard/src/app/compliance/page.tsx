"use client";

import { useEffect, useState } from "react";
import { FileCheck, Plus, RefreshCw, AlertTriangle, CheckCircle, Clock, ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { DataTable } from "@/components/data-table";
import {
  generateReport,
  listReports,
  getReport,
  type ComplianceReport,
  type ReportType,
  DEFAULT_TENANT_ID,
} from "@/lib/api";

export default function CompliancePage() {
  const [reports, setReports] = useState<ComplianceReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [generating, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showGenerate, setShowGenerate] = useState(false);
  const [selectedReport, setSelectedReport] = useState<ComplianceReport | null>(null);

  // Form state
  const [reportType, setReportType] = useState<ReportType>("soc2");
  const [periodStart, setPeriodStart] = useState("");
  const [periodEnd, setPeriodEnd] = useState("");

  const tenantId = typeof window !== "undefined" 
    ? localStorage.getItem("llmtrace_tenant_id") || DEFAULT_TENANT_ID 
    : DEFAULT_TENANT_ID;

  async function loadReports() {
    setLoading(true);
    try {
      const res = await listReports({ limit: 50 }, tenantId);
      setReports(res.data || []);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load reports");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadReports();
  }, [tenantId]);

  async function handleGenerate() {
    if (!periodStart || !periodEnd) {
      alert("Please select both start and end dates");
      return;
    }
    setSaving(true);
    try {
      const start = new Date(periodStart).toISOString();
      const end = new Date(periodEnd).toISOString();
      await generateReport(reportType, start, end, tenantId);
      setShowGenerate(false);
      await loadReports();
    } catch (e) {
      alert(e instanceof Error ? e.message : "Failed to generate report");
    } finally {
      setSaving(false);
    }
  }

  async function viewReport(id: string) {
    try {
      const report = await getReport(id, tenantId);
      setSelectedReport(report);
    } catch (e) {
      alert("Failed to load report details");
    }
  }

  const columns = [
    {
      header: "Type",
      accessor: (r: ComplianceReport) => <span className="font-bold uppercase text-xs">{r.report_type}</span>,
    },
    {
      header: "Period",
      accessor: (r: ComplianceReport) => (
        <span className="text-xs text-muted-foreground">
          {new Date(r.period_start).toLocaleDateString()} – {new Date(r.period_end).toLocaleDateString()}
        </span>
      ),
    },
    {
      header: "Status",
      accessor: (r: ComplianceReport) => {
        const variants: Record<string, "default" | "secondary" | "destructive" | "outline"> = {
          completed: "secondary",
          pending: "outline",
          failed: "destructive",
        };
        return <Badge variant={variants[r.status] || "default"}>{r.status}</Badge>;
      },
    },
    {
      header: "Requested",
      accessor: (r: ComplianceReport) => new Date(r.created_at).toLocaleString(),
    },
    {
      header: "Actions",
      accessor: (r: ComplianceReport) => (
        <Button 
          variant="ghost" 
          size="sm" 
          onClick={() => viewReport(r.id)}
          disabled={r.status === "pending"}
        >
          <ExternalLink className="mr-2 h-3 w-3" /> View
        </Button>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold">Compliance</h1>
        <div className="flex gap-2">
          <Button variant="outline" onClick={loadReports}>
            <RefreshCw className="mr-2 h-4 w-4" /> Refresh
          </Button>
          <Button onClick={() => setShowGenerate(!showGenerate)}>
            <Plus className="mr-2 h-4 w-4" /> Generate Report
          </Button>
        </div>
      </div>

      {showGenerate && (
        <Card className="border-primary bg-primary/5">
          <CardHeader>
            <CardTitle className="text-base">Generate New Report</CardTitle>
            <CardDescription>Select report type and time range</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-wrap items-end gap-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Report Type</label>
              <select 
                name="report_type"
                value={reportType} 
                onChange={(e) => setReportType(e.target.value as ReportType)}
                className="w-48 rounded-md border bg-background px-3 py-2 text-sm"
              >
                <option value="soc2">SOC2 Audit Trail</option>
                <option value="gdpr">GDPR Data Processing</option>
                <option value="hipaa">HIPAA Access Log</option>
              </select>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Period Start</label>
              <input 
                type="date" 
                value={periodStart}
                onChange={(e) => setPeriodStart(e.target.value)}
                className="rounded-md border bg-background px-3 py-2 text-sm"
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Period End</label>
              <input 
                type="date" 
                value={periodEnd}
                onChange={(e) => setPeriodEnd(e.target.value)}
                className="rounded-md border bg-background px-3 py-2 text-sm"
              />
            </div>
            <Button onClick={handleGenerate} disabled={generating}>
              {generating ? "Generating..." : "Start Generation"}
            </Button>
          </CardContent>
        </Card>
      )}

      {selectedReport && (
        <Card className="border-green-600 bg-green-500/5">
          <CardHeader className="flex flex-row items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <CheckCircle className="h-5 w-5 text-green-600" />
                {selectedReport.report_type.toUpperCase()} Report Details
              </CardTitle>
              <CardDescription>
                Period: {new Date(selectedReport.period_start).toLocaleDateString()} to {new Date(selectedReport.period_end).toLocaleDateString()}
              </CardDescription>
            </div>
            <Button variant="ghost" size="sm" onClick={() => setSelectedReport(null)}>Close</Button>
          </CardHeader>
          <CardContent>
            <div className="rounded-md border bg-background p-4 overflow-auto max-h-[400px]">
              <pre className="text-xs">
                {JSON.stringify(selectedReport.content || selectedReport.error || "No content", null, 2)}
              </pre>
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Existing Reports</CardTitle>
          <CardDescription>Cluster-wide compliance history</CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="py-8 text-center text-sm text-muted-foreground italic">Loading report history…</div>
          ) : (
            <DataTable 
              columns={columns} 
              data={reports} 
              emptyMessage="No compliance reports generated yet." 
            />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
