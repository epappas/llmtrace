"use client";

import { useEffect, useState } from "react";
import { AlertTriangle, Check, Copy, Server } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

interface RuntimeInfo {
  proxy_url: string | null;
}

function copy(text: string): void {
  if (navigator.clipboard && window.isSecureContext) {
    void navigator.clipboard.writeText(text);
    return;
  }
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.style.position = "fixed";
  ta.style.left = "-9999px";
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  document.execCommand("copy");
  document.body.removeChild(ta);
}

function curlExample(proxyUrl: string): string {
  return `curl -X POST ${proxyUrl}/v1/chat/completions \\
  -H "Authorization: Bearer <your-operator-key>" \\
  -H "Content-Type: application/json" \\
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'`;
}

/**
 * Surfaces the proxy public URL to tenant operators on the `/tenants` page.
 * The URL itself comes from `LLMTRACE_PROXY_URL` in the dashboard pod's env
 * (set at provision time by `deployments/basilica/lifecycle.py`). We fetch
 * it through a thin server route so this stays a client component (the
 * surrounding tenants page is interactive) without exposing the env var to
 * the browser at build time.
 */
export function ProxyConnectionBanner(): React.ReactElement | null {
  const [proxyUrl, setProxyUrl] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [copiedKey, setCopiedKey] = useState<"url" | "curl" | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch("/api/runtime/info", { cache: "no-store" })
      .then((res) => (res.ok ? res.json() : null))
      .then((body: RuntimeInfo | null) => {
        if (cancelled) return;
        setProxyUrl(body?.proxy_url ?? null);
        setLoaded(true);
      })
      .catch(() => {
        if (cancelled) return;
        setLoaded(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  function handleCopy(key: "url" | "curl", value: string): void {
    copy(value);
    setCopiedKey(key);
    window.setTimeout(() => setCopiedKey((cur) => (cur === key ? null : cur)), 2000);
  }

  if (!loaded) return null;

  if (!proxyUrl) {
    return (
      <Card className="border-yellow-500/40 bg-yellow-500/5" data-testid="proxy-connection-banner-missing">
        <CardHeader className="flex flex-row items-center gap-3 space-y-0">
          <AlertTriangle className="h-5 w-5 text-yellow-600" />
          <div>
            <CardTitle className="text-base">Proxy URL not configured</CardTitle>
            <CardDescription>
              The dashboard was provisioned without <code>LLMTRACE_PROXY_URL</code>.
              Set it on the dashboard pod env so this card can render the URL
              tenants need for runtime traffic.
            </CardDescription>
          </div>
        </CardHeader>
      </Card>
    );
  }

  return (
    <Card data-testid="proxy-connection-banner">
      <CardHeader className="flex flex-row items-center justify-between space-y-0">
        <div className="flex items-center gap-3">
          <Server className="h-5 w-5 text-primary" />
          <div>
            <CardTitle className="text-base">Proxy URL</CardTitle>
            <CardDescription>
              Your applications POST <code>/v1/*</code> traffic here using an
              operator-role API key.
            </CardDescription>
          </div>
        </div>
        <Badge variant="secondary">Public</Badge>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center gap-2 rounded-md border bg-background p-2">
          <code className="flex-1 break-all font-mono text-xs" data-testid="proxy-connection-banner-url">
            {proxyUrl}
          </code>
          <Button
            size="icon"
            variant="ghost"
            className="h-8 w-8"
            onClick={() => handleCopy("url", proxyUrl)}
            data-testid="proxy-connection-banner-copy-url"
          >
            {copiedKey === "url" ? <Check className="h-4 w-4 text-green-500" /> : <Copy className="h-4 w-4" />}
          </Button>
        </div>

        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <p className="text-xs font-medium text-muted-foreground">Example request</p>
            <Button
              size="sm"
              variant="ghost"
              className="h-7 text-xs"
              onClick={() => handleCopy("curl", curlExample(proxyUrl))}
              data-testid="proxy-connection-banner-copy-curl"
            >
              {copiedKey === "curl" ? <Check className="mr-2 h-3 w-3 text-green-500" /> : <Copy className="mr-2 h-3 w-3" />}
              Copy curl
            </Button>
          </div>
          <pre className="overflow-x-auto rounded-md bg-muted/40 p-3 text-xs">
            <code className="font-mono whitespace-pre">{curlExample(proxyUrl)}</code>
          </pre>
        </div>

        <p className="text-xs text-muted-foreground">
          Mint and manage operator keys per tenant below. Operator keys cannot
          access admin endpoints (`/api/v1/auth/keys`, `/api/v1/tenants`, ...) —
          those require an admin key.
        </p>
      </CardContent>
    </Card>
  );
}
