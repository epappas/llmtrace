"use client";

import { useEffect, useState } from "react";
import { RefreshCw, HeartPulse, Activity, ExternalLink } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

interface EndpointCheck {
  path: string;
  label: string;
  status: "idle" | "loading" | "ok" | "error";
  httpCode?: number;
  contentType?: string;
  preview?: string;
  error?: string;
}

interface MetricSample {
  name: string;
  value: string;
}

const ENDPOINTS: Array<Pick<EndpointCheck, "path" | "label">> = [
  { label: "Dashboard Health", path: "/health" },
  { label: "Dashboard Metrics", path: "/metrics" },
  { label: "Proxy Health", path: "/api/proxy/health" },
  { label: "Proxy Metrics", path: "/api/proxy/metrics" },
];

function statusBadge(item: EndpointCheck) {
  if (item.status === "ok") {
    return <Badge className="bg-green-100 text-green-800 hover:bg-green-100">Healthy</Badge>;
  }
  if (item.status === "error") {
    return <Badge variant="destructive">Error</Badge>;
  }
  if (item.status === "loading") {
    return <Badge variant="secondary">Checking</Badge>;
  }
  return <Badge variant="secondary">Unknown</Badge>;
}

function formatJsonPreview(preview: string): string {
  try {
    const parsed = JSON.parse(preview);
    return JSON.stringify(parsed, null, 2);
  } catch {
    return preview;
  }
}

function parseMetricSamples(preview: string): MetricSample[] {
  const samples: MetricSample[] = [];
  const lines = preview.split("\n");

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }

    const lastSpace = line.lastIndexOf(" ");
    if (lastSpace <= 0 || lastSpace === line.length - 1) {
      continue;
    }

    const name = line.slice(0, lastSpace);
    const value = line.slice(lastSpace + 1);
    samples.push({ name, value });

    if (samples.length >= 8) {
      break;
    }
  }

  return samples;
}

function renderEndpointBody(item: EndpointCheck) {
  if (item.error) {
    return (
      <pre className="max-h-56 overflow-auto rounded-md border border-red-200 bg-red-50 p-3 text-xs text-red-800">
        {item.error}
      </pre>
    );
  }

  if (!item.preview) {
    return (
      <pre className="max-h-56 overflow-auto rounded-md border bg-muted/30 p-3 text-xs">
        No response yet.
      </pre>
    );
  }

  const isJson =
    item.contentType?.includes("application/json") || item.path.includes("health");
  const isMetrics = item.path.includes("metrics");

  if (isJson) {
    return (
      <pre className="max-h-56 overflow-auto rounded-md border bg-muted/30 p-3 text-xs">
        {formatJsonPreview(item.preview)}
      </pre>
    );
  }

  if (isMetrics) {
    const samples = parseMetricSamples(item.preview);
    return (
      <div className="space-y-3">
        <div className="rounded-md border bg-background/60 p-3">
          <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            Top Signals
          </div>
          {samples.length > 0 ? (
            <div className="space-y-1">
              {samples.map((sample) => (
                <div
                  key={sample.name}
                  className="grid grid-cols-[1fr_auto] items-center gap-3 text-xs"
                >
                  <span className="truncate font-mono text-muted-foreground">
                    {sample.name}
                  </span>
                  <span className="font-mono">{sample.value}</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-xs text-muted-foreground">
              No metric samples parsed yet.
            </div>
          )}
        </div>
        <pre className="max-h-56 overflow-auto rounded-md border bg-muted/30 p-3 text-xs">
          {item.preview}
        </pre>
      </div>
    );
  }

  return (
    <pre className="max-h-56 overflow-auto rounded-md border bg-muted/30 p-3 text-xs">
      {item.preview}
    </pre>
  );
}

async function probeEndpoint(path: string, label: string): Promise<EndpointCheck> {
  try {
    const response = await fetch(path, { cache: "no-store" });
    const contentType = response.headers.get("content-type") ?? "unknown";
    const body = await response.text();
    const preview = body.slice(0, 4000);
    return {
      label,
      path,
      status: response.ok ? "ok" : "error",
      httpCode: response.status,
      contentType,
      preview,
    };
  } catch (error) {
    return {
      label,
      path,
      status: "error",
      error: error instanceof Error ? error.message : "Unknown request error",
    };
  }
}

export default function StatusPage() {
  const [items, setItems] = useState<EndpointCheck[]>(
    ENDPOINTS.map((endpoint) => ({ ...endpoint, status: "idle" })),
  );
  const [refreshing, setRefreshing] = useState(false);

  async function runChecks() {
    setRefreshing(true);
    setItems((prev) =>
      prev.map((item) => ({
        ...item,
        status: "loading",
        error: undefined,
      })),
    );

    const results = await Promise.all(
      ENDPOINTS.map((endpoint) => probeEndpoint(endpoint.path, endpoint.label)),
    );
    setItems(results);
    setRefreshing(false);
  }

  useEffect(() => {
    void runChecks();
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Status</h1>
          <p className="text-sm text-muted-foreground">
            Central place for health and metrics endpoints.
          </p>
        </div>
        <Button variant="outline" onClick={runChecks} disabled={refreshing}>
          <RefreshCw className={`mr-2 h-4 w-4 ${refreshing ? "animate-spin" : ""}`} />
          Refresh
        </Button>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        {items.map((item) => (
          <Card key={item.path}>
            <CardHeader>
              <div className="flex items-center justify-between gap-3">
                <CardTitle className="text-base flex items-center gap-2">
                  {item.path.includes("metrics") ? (
                    <Activity className="h-4 w-4 text-primary" />
                  ) : (
                    <HeartPulse className="h-4 w-4 text-primary" />
                  )}
                  {item.label}
                </CardTitle>
                {statusBadge(item)}
              </div>
              <CardDescription className="flex items-center gap-2">
                <a
                  href={item.path}
                  target="_blank"
                  rel="noreferrer"
                  className="font-mono text-xs underline underline-offset-2"
                >
                  {item.path}
                </a>
                <ExternalLink className="h-3 w-3" />
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="text-xs text-muted-foreground">
                HTTP: {item.httpCode ?? "n/a"} | Type: {item.contentType ?? "n/a"}
              </div>
              {renderEndpointBody(item)}
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
