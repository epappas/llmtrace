"use client";

import { useEffect, useState } from "react";
import { RefreshCw, CheckCircle, XCircle } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";

interface HealthStatus {
  status: string;
  storage?: { healthy: boolean };
  security?: { healthy: boolean };
}

export default function SettingsPage() {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [apiUrl] = useState(
    process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080",
  );

  async function checkHealth() {
    setLoading(true);
    try {
      const res = await fetch("/api/proxy/health");
      setHealth(await res.json());
    } catch {
      setHealth({ status: "unreachable" });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    checkHealth();
  }, []);

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold">Settings</h1>

      {/* Connection */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">API Connection</CardTitle>
          <CardDescription>
            The dashboard connects to the LLMTrace proxy REST API.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-4">
            <div className="flex-1">
              <label className="text-xs text-muted-foreground">Backend URL</label>
              <p className="font-mono text-sm">{apiUrl}</p>
            </div>
            <div>
              <label className="text-xs text-muted-foreground">Status</label>
              <div className="flex items-center gap-2">
                {health?.status === "ok" ? (
                  <>
                    <CheckCircle className="h-4 w-4 text-green-500" />
                    <Badge variant="secondary" className="bg-green-100 text-green-800">
                      Connected
                    </Badge>
                  </>
                ) : (
                  <>
                    <XCircle className="h-4 w-4 text-destructive" />
                    <Badge variant="destructive">Disconnected</Badge>
                  </>
                )}
              </div>
            </div>
            <Button variant="outline" size="sm" onClick={checkHealth} disabled={loading}>
              <RefreshCw className={`mr-2 h-4 w-4 ${loading ? "animate-spin" : ""}`} />
              Check
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Environment */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Environment Variables</CardTitle>
          <CardDescription>
            Configure the dashboard via environment variables.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b bg-muted/50">
                  <th className="px-4 py-2 text-left font-medium">Variable</th>
                  <th className="px-4 py-2 text-left font-medium">Description</th>
                  <th className="px-4 py-2 text-left font-medium">Default</th>
                </tr>
              </thead>
              <tbody>
                <tr className="border-b">
                  <td className="px-4 py-2 font-mono text-xs">NEXT_PUBLIC_API_URL</td>
                  <td className="px-4 py-2">LLMTrace proxy base URL (client-side)</td>
                  <td className="px-4 py-2 text-muted-foreground">http://localhost:8080</td>
                </tr>
                <tr className="border-b">
                  <td className="px-4 py-2 font-mono text-xs">LLMTRACE_API_URL</td>
                  <td className="px-4 py-2">LLMTrace proxy base URL (server-side proxy routes)</td>
                  <td className="px-4 py-2 text-muted-foreground">http://localhost:8080</td>
                </tr>
                <tr>
                  <td className="px-4 py-2 font-mono text-xs">PORT</td>
                  <td className="px-4 py-2">Dashboard listen port</td>
                  <td className="px-4 py-2 text-muted-foreground">3000</td>
                </tr>
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {/* API Endpoints Reference */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">API Endpoints</CardTitle>
          <CardDescription>
            Available LLMTrace REST API endpoints.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b bg-muted/50">
                  <th className="px-4 py-2 text-left font-medium">Method</th>
                  <th className="px-4 py-2 text-left font-medium">Path</th>
                  <th className="px-4 py-2 text-left font-medium">Description</th>
                </tr>
              </thead>
              <tbody>
                {[
                  ["GET", "/api/v1/traces", "List traces with filters"],
                  ["GET", "/api/v1/traces/:id", "Get trace with all spans"],
                  ["GET", "/api/v1/spans", "List spans with filters"],
                  ["GET", "/api/v1/spans/:id", "Get a single span"],
                  ["GET", "/api/v1/stats", "Storage statistics"],
                  ["GET", "/api/v1/security/findings", "Spans with security findings"],
                  ["GET", "/api/v1/costs/current", "Current spend per budget window"],
                  ["GET", "/api/v1/actions/summary", "Agent actions aggregate"],
                  ["GET", "/api/v1/tenants", "List tenants"],
                  ["POST", "/api/v1/tenants", "Create tenant"],
                  ["PUT", "/api/v1/tenants/:id", "Update tenant"],
                  ["DELETE", "/api/v1/tenants/:id", "Delete tenant"],
                  ["GET", "/health", "Health check"],
                ].map(([method, path, desc], i) => (
                  <tr key={i} className="border-b last:border-0">
                    <td className="px-4 py-2">
                      <Badge variant={method === "GET" ? "secondary" : "default"}>
                        {method}
                      </Badge>
                    </td>
                    <td className="px-4 py-2 font-mono text-xs">{path}</td>
                    <td className="px-4 py-2 text-muted-foreground">{desc}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
