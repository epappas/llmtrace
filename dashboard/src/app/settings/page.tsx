"use client";

import { useEffect, useState } from "react";
import { RefreshCw, CheckCircle, XCircle, ExternalLink } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { healthCheck } from "@/lib/api";

interface HealthStatus {
  status: string;
  storage?: { healthy: boolean };
  security?: { healthy: boolean };
}

interface LiveConfigPayload {
  config: Record<string, unknown>;
}

function humanizeKey(key: string): string {
  return key
    .replace(/_/g, " ")
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function formatPrimitive(value: string | number | boolean | null): string {
  if (value === null) return "Not set";
  if (typeof value === "boolean") return value ? "Enabled" : "Disabled";
  return String(value);
}

function renderConfigValue(value: unknown, depth = 0) {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    const text = formatPrimitive(value);
    const isRedacted = text === "***redacted***";
    return (
      <span className={isRedacted ? "font-mono text-amber-700" : "font-mono"}>
        {isRedacted ? "Redacted" : text}
      </span>
    );
  }

  if (Array.isArray(value)) {
    if (value.length === 0) {
      return <span className="text-muted-foreground">None</span>;
    }
    return (
      <div className="space-y-2">
        {value.map((item, index) => (
          <div
            key={`${depth}-${index}`}
            className="rounded-md border bg-background/50 p-2"
          >
            {renderConfigValue(item, depth + 1)}
          </div>
        ))}
      </div>
    );
  }

  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length === 0) {
      return <span className="text-muted-foreground">None</span>;
    }

    return (
      <div className="space-y-2">
        {entries.map(([key, nested]) => (
          <div
            key={`${depth}-${key}`}
            className="grid gap-2 rounded-md border bg-background/50 p-3 md:grid-cols-[240px_1fr]"
          >
            <div className="text-sm font-medium">{humanizeKey(key)}</div>
            <div className="text-sm">{renderConfigValue(nested, depth + 1)}</div>
          </div>
        ))}
      </div>
    );
  }

  return <span className="text-muted-foreground">Unsupported value</span>;
}

function joinUrl(base: string, path: string): string {
  const trimmedBase = base.replace(/\/+$/, "");
  const trimmedPath = path.startsWith("/") ? path : `/${path}`;
  return `${trimmedBase}${trimmedPath}`;
}

export default function SettingsPage() {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [liveConfig, setLiveConfig] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(false);
  const [configLoading, setConfigLoading] = useState(false);
  const [apiUrl] = useState(
    process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080",
  );
  const swaggerUiUrl = joinUrl(apiUrl, "/swagger-ui/");
  const openApiJsonUrl = joinUrl(apiUrl, "/api-doc/openapi.json");

  async function checkHealth() {
    console.log("[Settings] Checking health via API helper...");
    setLoading(true);
    try {
      const data = await healthCheck();
      console.log("[Settings] Health check response:", data);
      setHealth(data);
    } catch (e) {
      console.error("[Settings] Health check failed:", e);
      setHealth({ status: "unreachable" });
    } finally {
      setLoading(false);
    }
  }

  async function fetchLiveConfig() {
    setConfigLoading(true);
    try {
      const response = await fetch("/api/v1/config/live", { cache: "no-store" });
      if (!response.ok) {
        throw new Error(`Failed to load config: ${response.status}`);
      }
      const data = (await response.json()) as LiveConfigPayload;
      setLiveConfig(data.config);
    } catch {
      setLiveConfig(null);
    } finally {
      setConfigLoading(false);
    }
  }

  useEffect(() => {
    checkHealth();
    fetchLiveConfig();
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
                {health?.status === "ok" || health?.status === "healthy" ? (
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

      {/* Current Configuration */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Current Configuration</CardTitle>
          <CardDescription>
            Redacted runtime configuration currently loaded by the proxy server.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <Button variant="outline" size="sm" onClick={fetchLiveConfig} disabled={configLoading}>
            <RefreshCw className={`mr-2 h-4 w-4 ${configLoading ? "animate-spin" : ""}`} />
            Refresh Config
          </Button>
          <div className="rounded-md border bg-muted/20 p-3">
            {liveConfig ? (
              <div className="max-h-[520px] overflow-auto pr-1">
                {renderConfigValue(liveConfig)}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">Live configuration unavailable.</p>
            )}
          </div>
        </CardContent>
      </Card>

      {/* API Endpoints Reference */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">API Endpoints</CardTitle>
          <CardDescription>
            Interactive Swagger UI served by the LLMTrace proxy.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-2">
              <Button asChild variant="outline" size="sm">
                <a href={swaggerUiUrl} target="_blank" rel="noreferrer">
                  <ExternalLink className="mr-2 h-4 w-4" />
                  Open Swagger UI
                </a>
              </Button>
              <Button asChild variant="outline" size="sm">
                <a href={openApiJsonUrl} target="_blank" rel="noreferrer">
                  <ExternalLink className="mr-2 h-4 w-4" />
                  Open OpenAPI JSON
                </a>
              </Button>
              <span className="text-xs text-muted-foreground">
                Uses <span className="font-mono">NEXT_PUBLIC_API_URL</span> ({apiUrl})
              </span>
            </div>

            <div className="rounded-md border">
              <iframe
                title="LLMTrace Swagger UI"
                src={swaggerUiUrl}
                className="h-[70vh] w-full rounded-md"
              />
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
