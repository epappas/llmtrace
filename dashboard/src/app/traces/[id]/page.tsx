"use client";

import { useEffect, useState, use } from "react";
import { useParams, useSearchParams } from "next/navigation";
import Link from "next/link";
import { ArrowLeft } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Separator } from "@/components/ui/separator";
import { type TraceEvent, getTrace, findActiveTenant } from "@/lib/api";

export default function TraceDetailPage(props: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ [key: string]: string | string[] | undefined }>;
}) {
  const { id } = use(props.params);
  const searchParams = use(props.searchParams);
  const [trace, setTrace] = useState<TraceEvent | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const queryTenant = searchParams.tenant as string | null;
        const tenantId = queryTenant || await findActiveTenant();
        const data = await getTrace(id, tenantId);
        setTrace(data);
      } catch {
        /* ignore */
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [id, searchParams]);

  if (loading) return <p className="text-sm text-muted-foreground">Loading…</p>;
  if (!trace) {
    return (
      <div className="space-y-4">
        <Link href="/traces">
          <Button variant="ghost" size="sm">
            <ArrowLeft className="mr-2 h-4 w-4" /> Back to Traces
          </Button>
        </Link>
        <p className="text-sm text-muted-foreground">Trace not found.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <Link href="/traces">
          <Button variant="ghost" size="sm">
            <ArrowLeft className="mr-2 h-4 w-4" /> Back
          </Button>
        </Link>
        <h1 className="text-2xl font-bold">
          Trace <span className="font-mono text-lg">{trace.trace_id.slice(0, 12)}…</span>
        </h1>
      </div>

      {/* Summary */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Trace ID</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="break-all font-mono text-xs">{trace.trace_id}</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Created</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm">{new Date(trace.created_at).toLocaleString()}</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Spans</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">{trace.spans.length}</p>
          </CardContent>
        </Card>
      </div>

      {/* Spans */}
      {trace.spans.map((span, idx) => {
        const latencyMs = span.duration_ms ?? span.latency_ms ?? null;
        const ttftMs = span.time_to_first_token_ms ?? span.ttft_ms ?? null;
        const totalTokens =
          span.total_tokens ??
          (span.prompt_tokens != null && span.completion_tokens != null
            ? span.prompt_tokens + span.completion_tokens
            : null);

        return (
          <Card key={span.span_id}>
          <CardHeader>
            <CardTitle className="flex items-center gap-3 text-base">
              Span {idx + 1}: {span.operation_name}
              <Badge variant="secondary">{span.provider}</Badge>
              <Badge variant="outline">{span.model_name}</Badge>
              {span.security_score > 0 && (
                <Badge variant={span.security_score >= 70 ? "destructive" : "default"}>
                  Security: {span.security_score}
                </Badge>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="details">
              <TabsList>
                <TabsTrigger value="details">Details</TabsTrigger>
                <TabsTrigger value="prompt">Prompt</TabsTrigger>
                <TabsTrigger value="response">Response</TabsTrigger>
                {(span.security_findings?.length ?? 0) > 0 && (
                  <TabsTrigger value="security">
                    Security ({span.security_findings.length})
                  </TabsTrigger>
                )}
                {(span.agent_actions?.length ?? 0) > 0 && (
                  <TabsTrigger value="actions">
                    Actions ({span.agent_actions.length})
                  </TabsTrigger>
                )}
              </TabsList>

              <TabsContent value="details" className="space-y-3 pt-4">
                <div className="grid gap-2 text-sm md:grid-cols-2">
                  <div>
                    <span className="text-muted-foreground">Span ID:</span>{" "}
                    <span className="font-mono text-xs">{span.span_id}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Prompt Tokens:</span>{" "}
                    {span.prompt_tokens ?? "—"}
                  </div>
                  <div>
                    <span className="text-muted-foreground">Completion Tokens:</span>{" "}
                    {span.completion_tokens ?? "—"}
                  </div>
                  <div>
                    <span className="text-muted-foreground">Total Tokens:</span>{" "}
                    {totalTokens ?? "—"}
                  </div>
                  <div>
                    <span className="text-muted-foreground">Latency:</span>{" "}
                    {latencyMs != null ? `${latencyMs}ms` : "—"}
                  </div>
                  <div>
                    <span className="text-muted-foreground">TTFT:</span>{" "}
                    {ttftMs != null ? `${ttftMs}ms` : "—"}
                  </div>
                  <div>
                    <span className="text-muted-foreground">Cost:</span>{" "}
                    {span.estimated_cost_usd != null
                      ? `$${span.estimated_cost_usd.toFixed(6)}`
                      : "—"}
                  </div>
                </div>
              </TabsContent>

              <TabsContent value="prompt" className="pt-4">
                <pre className="max-h-96 overflow-auto rounded-md bg-muted p-4 text-xs">
                  {span.prompt || "No prompt captured"}
                </pre>
              </TabsContent>

              <TabsContent value="response" className="pt-4">
                <pre className="max-h-96 overflow-auto rounded-md bg-muted p-4 text-xs">
                  {span.response || "No response captured"}
                </pre>
              </TabsContent>

              {(span.security_findings?.length ?? 0) > 0 && (
                <TabsContent value="security" className="space-y-3 pt-4">
                  {span.security_findings.map((f) => (
                    <div key={f.id} className="rounded-md border p-3">
                      <div className="flex items-center gap-2">
                        <Badge
                          variant={
                            f.severity === "Critical" || f.severity === "High"
                              ? "destructive"
                              : "secondary"
                          }
                        >
                          {f.severity}
                        </Badge>
                        <span className="text-sm font-medium">{f.finding_type}</span>
                        <span className="ml-auto text-xs text-muted-foreground">
                          Confidence: {(f.confidence * 100).toFixed(0)}%
                        </span>
                      </div>
                      <Separator className="my-2" />
                      <p className="text-sm text-muted-foreground">{f.description}</p>
                    </div>
                  ))}
                </TabsContent>
              )}

              {(span.agent_actions?.length ?? 0) > 0 && (
                <TabsContent value="actions" className="space-y-3 pt-4">
                  {span.agent_actions.map((a) => (
                    <div key={a.id} className="rounded-md border p-3">
                      <div className="flex items-center gap-2">
                        <Badge variant="outline">{a.action_type}</Badge>
                        <span className="text-sm font-medium">{a.name}</span>
                        <Badge variant={a.success ? "secondary" : "destructive"}>
                          {a.success ? "Success" : "Failed"}
                        </Badge>
                        {a.duration_ms != null && (
                          <span className="ml-auto text-xs text-muted-foreground">
                            {a.duration_ms}ms
                          </span>
                        )}
                      </div>
                      {a.arguments && (
                        <pre className="mt-2 max-h-32 overflow-auto rounded bg-muted p-2 text-xs">
                          {a.arguments}
                        </pre>
                      )}
                    </div>
                  ))}
                </TabsContent>
              )}
            </Tabs>
          </CardContent>
          </Card>
        );
      })}
    </div>
  );
}
