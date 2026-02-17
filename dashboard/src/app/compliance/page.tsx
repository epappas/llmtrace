"use client";

import { useEffect, useState, useRef } from "react";
import { FileCheck, Plus, RefreshCw, AlertTriangle, CheckCircle, Clock, ExternalLink, Download, ShieldCheck, Lock, Globe, Activity, Printer, ChevronDown, ChevronRight } from "lucide-react";
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
  const [showRaw, setShowRaw] = useState(false);
  const printRef = useRef<HTMLDivElement>(null);
  
  // Extract data with fallback for both nested and flat structures
  const data = report.content?.data || report.content || {};
  const type = (report.report_type || "").toLowerCase();

  const downloadJson = () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `llmtrace-report-${type}-${report.id.slice(0, 8)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handlePrint = () => {
    window.print();
  };

  const renderSoc2 = (d: any) => (
    <div className="grid gap-6 md:grid-cols-2">
      <div className="space-y-3">
        <h4 className="text-sm font-bold flex items-center gap-2 text-primary uppercase tracking-wider">
          <Activity className="h-4 w-4" /> Activity Summary
        </h4>
        <div className="grid gap-2">
          <div className="flex justify-between items-center rounded-lg border bg-background px-4 py-3 shadow-sm">
            <span className="text-sm font-medium">Total Traces Processed</span>
            <Badge variant="secondary" className="font-mono text-base">{d.total_traces_processed ?? 0}</Badge>
          </div>
          <div className="flex justify-between items-center rounded-lg border bg-background px-4 py-3 shadow-sm">
            <span className="text-sm font-medium">Audit Trail Events</span>
            <Badge variant="secondary" className="font-mono text-base">{d.total_audit_events ?? 0}</Badge>
          </div>
          <div className="flex justify-between items-center rounded-lg border bg-background px-4 py-3 shadow-sm">
            <span className="text-sm font-medium">Access Management Actions</span>
            <Badge variant="secondary" className="font-mono text-base">{d.access_control_events ?? 0}</Badge>
          </div>
        </div>
      </div>
      <div className="space-y-3">
        <h4 className="text-sm font-bold flex items-center gap-2 text-primary uppercase tracking-wider">
          <ShieldCheck className="h-4 w-4" /> Security Posture
        </h4>
        <div className="grid gap-2">
          <div className="flex justify-between items-center rounded-lg border bg-background px-4 py-3 shadow-sm">
            <span className="text-sm font-medium">Total Security Findings</span>
            <Badge variant={d.total_security_findings > 0 ? "destructive" : "secondary"} className="font-mono text-base">
              {d.total_security_findings ?? 0}
            </Badge>
          </div>
          <div className="rounded-lg border bg-background p-4 shadow-sm space-y-3">
            <span className="text-xs font-bold uppercase text-muted-foreground">Findings by Severity</span>
            <div className="grid grid-cols-2 gap-2">
              {Object.entries(d.findings_by_severity || { Critical: 0, High: 0, Medium: 0, Low: 0 }).map(([sev, count]: [string, any]) => (
                <div key={sev} className="flex justify-between items-center text-xs">
                  <span className="text-muted-foreground">{sev}</span>
                  <span className={`font-bold ${count > 0 && (sev === 'Critical' || sev === 'High') ? 'text-destructive' : ''}`}>{count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  const renderGdpr = (d: any) => (
    <div className="grid gap-6 md:grid-cols-2">
      <div className="space-y-3">
        <h4 className="text-sm font-bold flex items-center gap-2 text-primary uppercase tracking-wider">
          <Globe className="h-4 w-4" /> Data Processing
        </h4>
        <div className="grid gap-2">
          <div className="flex justify-between items-center rounded-lg border bg-background px-4 py-3 shadow-sm">
            <span className="text-sm font-medium">Processing Activities</span>
            <Badge variant="secondary" className="font-mono text-base">{d.total_processing_activities ?? 0}</Badge>
          </div>
          <div className="flex justify-between items-center rounded-lg border bg-background px-4 py-3 shadow-sm">
            <span className="text-sm font-medium">PII Related Findings</span>
            <Badge variant={d.pii_findings > 0 ? "destructive" : "secondary"} className="font-mono text-base">
              {d.pii_findings ?? 0}
            </Badge>
          </div>
        </div>
      </div>
      <div className="space-y-3">
        <h4 className="text-sm font-bold flex items-center gap-2 text-primary uppercase tracking-wider">
          <Lock className="h-4 w-4" /> Governance & Lifecycle
        </h4>
        <div className="grid gap-2">
          <div className="flex justify-between items-center rounded-lg border bg-background px-4 py-3 shadow-sm">
            <span className="text-sm font-medium">Data Lifecycle Events</span>
            <Badge variant="secondary" className="font-mono text-base">{d.data_lifecycle_events ?? 0}</Badge>
          </div>
          <div className="flex justify-between items-center rounded-lg border bg-background px-4 py-3 shadow-sm">
            <span className="text-sm font-medium">Unique Tenants Processed</span>
            <Badge variant="secondary" className="font-mono text-base">{d.tenants_processed ?? 0}</Badge>
          </div>
        </div>
      </div>
    </div>
  );

  const renderHipaa = (d: any) => (
    <div className="grid gap-6 md:grid-cols-2">
      <div className="space-y-3">
        <h4 className="text-sm font-bold flex items-center gap-2 text-primary uppercase tracking-wider">
          <Activity className="h-4 w-4" /> Access Audits
        </h4>
        <div className="grid gap-2">
          <div className="flex justify-between items-center rounded-lg border bg-background px-4 py-3 shadow-sm">
            <span className="text-sm font-medium">Total Access Events</span>
            <Badge variant="secondary" className="font-mono text-base">{d.total_access_events ?? 0}</Badge>
          </div>
          <div className="flex justify-between items-center rounded-lg border bg-background px-4 py-3 shadow-sm">
            <span className="text-sm font-medium">Unauthorized Access Findings</span>
            <Badge variant={d.unauthorized_access_findings > 0 ? "destructive" : "secondary"} className="font-mono text-base">
              {d.unauthorized_access_findings ?? 0}
            </Badge>
          </div>
        </div>
      </div>
      <div className="space-y-3">
        <h4 className="text-sm font-bold flex items-center gap-2 text-primary uppercase tracking-wider">
          <Lock className="h-4 w-4" /> Security Management
        </h4>
        <div className="grid gap-2">
          <div className="flex justify-between items-center rounded-lg border bg-background px-4 py-3 shadow-sm">
            <span className="text-sm font-medium">Failed Access Attempts</span>
            <Badge variant={d.failed_access_attempts > 0 ? "destructive" : "secondary"} className="font-mono text-base">
              {d.failed_access_attempts ?? 0}
            </Badge>
          </div>
          <div className="flex justify-between items-center rounded-lg border bg-background px-4 py-3 shadow-sm">
            <span className="text-sm font-medium">Policy/Access Changes</span>
            <Badge variant="secondary" className="font-mono text-base">{d.access_control_changes ?? 0}</Badge>
          </div>
        </div>
      </div>
    </div>
  );

  return (
    <div className="print:p-0">
      <Card className="border-green-600 bg-green-500/5 shadow-md print:border-none print:bg-white print:shadow-none">
        <CardHeader className="flex flex-row items-center justify-between pb-4 border-b">
          <div className="space-y-1">
            <CardTitle className="flex items-center gap-2 text-2xl">
              <CheckCircle className="h-6 w-6 text-green-600 print:text-black" />
              {report.report_type.toUpperCase()} Compliance Audit
            </CardTitle>
            <CardDescription className="text-sm font-medium">
              Generated: {new Date(report.created_at).toLocaleString()} <br />
              Reporting Period: {new Date(report.period_start).toLocaleDateString()} — {new Date(report.period_end).toLocaleDateString()}
            </CardDescription>
          </div>
          <div className="flex gap-2 print:hidden">
            <Button variant="outline" size="sm" onClick={handlePrint} className="gap-2">
              <Printer className="h-4 w-4" /> Print / PDF
            </Button>
            <Button
              data-testid="download-report-json-button"
              variant="outline"
              size="sm"
              onClick={downloadJson}
              className="gap-2"
            >
              <Download className="h-4 w-4" /> JSON
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-8 pt-6">
          {report.status === "failed" ? (
            <div className="p-6 bg-destructive/10 border border-destructive/20 text-destructive rounded-xl flex items-center gap-3">
              <AlertTriangle className="h-6 w-6" />
              <div>
                <p className="font-bold">Generation Error</p>
                <p className="text-sm opacity-90">{report.error || "Detailed data gathering failed for this period."}</p>
              </div>
            </div>
          ) : (
            <div ref={printRef}>
              {(type === "soc2") && renderSoc2(data)}
              {(type === "gdpr") && renderGdpr(data)}
              {(type === "hipaa") && renderHipaa(data)}
              
              {!(["soc2", "gdpr", "hipaa"].includes(type)) && (
                <div className="p-8 text-center text-muted-foreground italic border rounded-lg bg-background/50">
                  Select a report type to view summary visualization.
                </div>
              )}

              <div className="mt-8 pt-6 border-t print:hidden">
                <button
                  data-testid="report-raw-toggle"
                  onClick={() => setShowRaw(!showRaw)}
                  className="flex items-center gap-2 text-xs font-bold uppercase text-muted-foreground hover:text-foreground transition-colors"
                >
                  {showRaw ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                  Developer Audit Log (JSON)
                </button>
                
                {showRaw && (
                  <div className="mt-4 rounded-xl border bg-slate-950 p-4 shadow-inner">
                    <pre
                      data-testid="report-raw-content"
                      className="text-[10px] leading-relaxed text-slate-300 overflow-auto max-h-[300px] scrollbar-thin scrollbar-thumb-slate-700"
                    >
                      {JSON.stringify(report.content, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
              
              <div className="hidden print:block mt-12 text-[10px] text-muted-foreground border-t pt-4">
                This document was automatically generated by LLMTrace Security Proxy. 
                Report ID: {report.id} • Tenant: {report.tenant_id}
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
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
      // Scroll to viewer
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } catch (e) {
      alert("Failed to load report details");
    }
  }

  const columns = [
    {
      header: "Report Type",
      accessor: (r: ComplianceReport) => (
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-md bg-primary/10 text-primary">
            <FileCheck className="h-4 w-4" />
          </div>
          <span className="font-bold uppercase text-xs tracking-tight">{r.report_type}</span>
        </div>
      ),
    },
    {
      header: "Audit Period",
      accessor: (r: ComplianceReport) => (
        <div className="flex flex-col gap-0.5">
          <span className="text-xs font-medium">
            {new Date(r.period_start).toLocaleDateString()} – {new Date(r.period_end).toLocaleDateString()}
          </span>
          <span className="text-[10px] text-muted-foreground flex items-center gap-1">
            <Clock className="h-3 w-3" /> Requested {new Date(r.created_at).toLocaleDateString()}
          </span>
        </div>
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
        return (
          <Badge variant={variants[r.status] || "default"} className="capitalize px-2 py-0.5 text-[10px]">
            {r.status === "completed" && <CheckCircle className="mr-1 h-3 w-3" />}
            {r.status === "pending" && <RefreshCw className="mr-1 h-3 w-3 animate-spin" />}
            {r.status}
          </Badge>
        );
      },
    },
    {
      header: "",
      accessor: (r: ComplianceReport) => (
        <Button
          data-testid={`view-report-${r.id}`}
          variant="secondary"
          size="sm"
          className="h-8 px-3 text-xs gap-2"
          onClick={() => viewReport(r.id)}
          disabled={r.status === "pending"}
        >
          <ExternalLink className="h-3.5 w-3.5" /> View Report
        </Button>
      ),
      className: "text-right"
    },
  ];

  return (
    <div className="space-y-8 max-w-6xl mx-auto pb-12 print:m-0 print:p-0">
      <div className="flex items-center justify-between print:hidden">
        <div className="space-y-1">
          <h1 className="text-4xl font-extrabold tracking-tight">Compliance</h1>
          <p className="text-muted-foreground">Generate and manage regulatory audit reports for your LLM interactions.</p>
        </div>
        <div className="flex gap-3">
          <Button variant="outline" onClick={loadReports} className="shadow-sm">
            <RefreshCw className="mr-2 h-4 w-4" /> Refresh
          </Button>
          <Button
            data-testid="generate-report-toggle"
            onClick={() => setShowGenerate(!showGenerate)}
            className="shadow-md"
          >
            <Plus className="mr-2 h-4 w-4" /> Generate Report
          </Button>
        </div>
      </div>

      {selectedReport && (
        <div className="space-y-4 animate-in fade-in slide-in-from-top-4 duration-300">
          <div className="flex items-center justify-between print:hidden">
            <h2 data-testid="active-report-viewer" className="text-xl font-bold flex items-center gap-2">
              <div className="w-1.5 h-6 bg-green-600 rounded-full" />
              Active Viewer
            </h2>
            <Button
              data-testid="close-report-viewer"
              variant="ghost"
              size="sm"
              onClick={() => setSelectedReport(null)}
              className="text-muted-foreground"
            >
              Close Viewer
            </Button>
          </div>
          <ReportViewer report={selectedReport} />
        </div>
      )}

      {showGenerate && (
        <Card className="border-primary/20 bg-primary/5 shadow-lg animate-in zoom-in-95 duration-200 print:hidden">
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <Plus className="h-5 w-5 text-primary" />
              Configure Audit Report
            </CardTitle>
            <CardDescription>Select report type and time range for data aggregation</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-wrap items-end gap-6 pt-2">
            <div className="space-y-2">
              <label className="text-xs font-bold uppercase text-muted-foreground">Report Standard</label>
              <select 
                name="report_type"
                value={reportType}
                onChange={(e) => setReportType(e.target.value as ReportType)}
                className="w-56 h-10 rounded-md border border-input bg-background px-3 py-2 text-sm focus:ring-2 focus:ring-primary shadow-sm"
              >
                <option value="soc2">SOC2 Audit Trail</option>
                <option value="gdpr">GDPR Data Processing</option>
                <option value="hipaa">HIPAA Access Log</option>
              </select>
            </div>
            <div className="space-y-2">
              <label className="text-xs font-bold uppercase text-muted-foreground">Period Start</label>
              <input 
                type="date" 
                value={periodStart}
                onChange={(e) => setPeriodStart(e.target.value)}
                className="h-10 rounded-md border border-input bg-background px-3 py-2 text-sm focus:ring-2 focus:ring-primary shadow-sm"
              />
            </div>
            <div className="space-y-2">
              <label className="text-xs font-bold uppercase text-muted-foreground">Period End</label>
              <input 
                type="date" 
                value={periodEnd}
                onChange={(e) => setPeriodEnd(e.target.value)}
                className="h-10 rounded-md border border-input bg-background px-3 py-2 text-sm focus:ring-2 focus:ring-primary shadow-sm"
              />
            </div>
            <Button
              data-testid="generate-audit-button"
              onClick={handleGenerate}
              disabled={generating}
              className="h-10 px-8"
            >
              {generating ? "Gathering Data..." : "Generate Audit"}
            </Button>
          </CardContent>
        </Card>
      )}

      <Card className="shadow-sm print:hidden">
        <CardHeader className="pb-2">
          <CardTitle className="text-lg">Audit History</CardTitle>
          <CardDescription>All generated compliance records for the current tenant.</CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="py-12 text-center">
              <RefreshCw className="h-8 w-8 animate-spin mx-auto text-muted-foreground/40" />
              <p className="mt-4 text-sm text-muted-foreground animate-pulse">Retrieving audit history…</p>
            </div>
          ) : (
            <DataTable 
              columns={columns} 
              data={reports} 
              emptyMessage="No reports found. Generate your first audit to see it here." 
            />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
