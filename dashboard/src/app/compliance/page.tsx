"use client";

import { useEffect, useState } from "react";
import { FileCheck, Plus, RefreshCw, AlertTriangle, CheckCircle, Clock, ExternalLink, Download, ShieldCheck, Lock, Globe, Activity } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { DataTable } from "@/components/data-table";
import { Separator } from "@/components/ui/separator";
import {
  generateReport,
  listReports,
  getReport,
  type ComplianceReport,
  type ReportType,
  DEFAULT_TENANT_ID,
} from "@/lib/api";

function ReportViewer({ report }: { report: ComplianceReport }) {
  const data = report.content?.data || {};
  
  const downloadJson = () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `llmtrace-report-${report.report_type}-${report.id.slice(0, 8)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const renderSoc2 = (d: any) => (
    <div className="grid gap-4 md:grid-cols-2">
      <div className="space-y-2">
        <h4 className="text-sm font-semibold flex items-center gap-2"><Activity className="h-4 w-4" /> Activity Summary</h4>
        <div className="rounded-md border p-3 space-y-1">
          <div className="flex justify-between text-sm"><span>Total Traces</span><span className="font-mono">{d.total_traces_processed}</span></div>
          <div className="flex justify-between text-sm"><span>Audit Events</span><span className="font-mono">{d.total_audit_events}</span></div>
          <div className="flex justify-between text-sm"><span>Access Control Events</span><span className="font-mono">{d.access_control_events}</span></div>
        </div>
      </div>
      <div className="space-y-2">
        <h4 className="text-sm font-semibold flex items-center gap-2"><ShieldCheck className="h-4 w-4" /> Security Posture</h4>
        <div className="rounded-md border p-3 space-y-1">
          <div className="flex justify-between text-sm"><span>Total Findings</span><span className="font-mono">{d.total_security_findings}</span></div>
          {Object.entries(d.findings_by_severity || {}).map(([sev, count]: [string, any]) => (
            <div key={sev} className="flex justify-between text-xs text-muted-foreground ml-2">
              <span>{sev}</span><span>{count}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );

  const renderGdpr = (d: any) => (
    <div className="grid gap-4 md:grid-cols-2">
      <div className="space-y-2">
        <h4 className="text-sm font-semibold flex items-center gap-2"><Globe className="h-4 w-4" /> Data Processing</h4>
        <div className="rounded-md border p-3 space-y-1">
          <div className="flex justify-between text-sm"><span>Processing Activities</span><span className="font-mono">{d.total_processing_activities}</span></div>
          <div className="flex justify-between text-sm"><span>PII Findings</span><Badge variant={d.pii_findings > 0 ? "destructive" : "secondary"}>{d.pii_findings}</Badge></div>
        </div>
      </div>
      <div className="space-y-2">
        <h4 className="text-sm font-semibold flex items-center gap-2"><Lock className="h-4 w-4" /> Lifecycle Management</h4>
        <div className="rounded-md border p-3 space-y-1">
          <div className="flex justify-between text-sm"><span>Lifecycle Events</span><span className="font-mono">{d.data_lifecycle_events}</span></div>
          <div className="flex justify-between text-sm"><span>Tenants Impacted</span><span className="font-mono">{d.tenants_processed}</span></div>
        </div>
      </div>
    </div>
  );

  const renderHipaa = (d: any) => (
    <div className="grid gap-4 md:grid-cols-2">
      <div className="space-y-2">
        <h4 className="text-sm font-semibold flex items-center gap-2"><Activity className="h-4 w-4" /> Access Audits</h4>
        <div className="rounded-md border p-3 space-y-1">
          <div className="flex justify-between text-sm"><span>Total Access Events</span><span className="font-mono">{d.total_access_events}</span></div>
          <div className="flex justify-between text-sm"><span>Failed Attempts</span><Badge variant={d.failed_access_attempts > 0 ? "destructive" : "secondary"}>{d.failed_access_attempts}</Badge></div>
        </div>
      </div>
      <div className="space-y-2">
        <h4 className="text-sm font-semibold flex items-center gap-2"><Lock className="h-4 w-4" /> Governance</h4>
        <div className="rounded-md border p-3 space-y-1">
          <div className="flex justify-between text-sm"><span>Unauthorized Findings</span><Badge variant={d.unauthorized_access_findings > 0 ? "destructive" : "secondary"}>{d.unauthorized_access_findings}</Badge></div>
          <div className="flex justify-between text-sm"><span>Policy Changes</span><span className="font-mono">{d.access_control_changes}</span></div>
        </div>
      </div>
    </div>
  );

  return (
    <Card className="border-green-600 bg-green-500/5">
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <div className="space-y-1">
          <CardTitle className="flex items-center gap-2">
            <CheckCircle className="h-5 w-5 text-green-600" />
            {report.report_type.toUpperCase()} Compliance Report
          </CardTitle>
          <CardDescription>
            Generated on {new Date(report.created_at).toLocaleString()} • Period: {new Date(report.period_start).toLocaleDateString()} to {new Date(report.period_end).toLocaleDateString()}
          </CardDescription>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={downloadJson} className="gap-2">
            <Download className="h-4 w-4" /> JSON
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-6 pt-4">
        {report.status === "failed" ? (
          <div className="p-4 bg-destructive/10 border border-destructive/20 text-destructive rounded-md text-sm">
            <strong>Error:</strong> {report.error || "Report generation failed"}
          </div>
        ) : (
          <>
            {report.report_type === "soc2" && renderSoc2(data)}
            {report.report_type === "gdpr" && renderGdpr(data)}
            {report.report_type === "hipaa" && renderHipaa(data)}
            
            <Separator />
            
            <div className="space-y-2">
              <h4 className="text-xs font-bold uppercase text-muted-foreground">Raw Audit Data</h4>
              <div className="rounded-md border bg-background p-4 overflow-auto max-h-[200px]">
                <pre className="text-[10px] leading-tight">
                  {JSON.stringify(report.content, null, 2)}
                </pre>
              </div>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

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
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold">Report View</h2>
            <Button variant="ghost" size="sm" onClick={() => setSelectedReport(null)}>Close Viewer</Button>
          </div>
          <ReportViewer report={selectedReport} />
        </div>
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
