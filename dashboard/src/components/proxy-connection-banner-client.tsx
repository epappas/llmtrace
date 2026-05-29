"use client";

import { useState, type ReactElement } from "react";
import { AlertTriangle, Check, Copy, Link as LinkIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export interface ProxyConnectionBannerClientProps {
  proxyUrl: string;
}

function copyText(text: string): void {
  if (navigator.clipboard && window.isSecureContext) {
    void navigator.clipboard.writeText(text);
    return;
  }
  const textArea: HTMLTextAreaElement = document.createElement("textarea");
  textArea.value = text;
  textArea.style.position = "fixed";
  textArea.style.left = "-9999px";
  document.body.appendChild(textArea);
  textArea.focus();
  textArea.select();
  document.execCommand("copy");
  document.body.removeChild(textArea);
}

function buildCurlExample(proxyUrl: string): string {
  return [
    `curl -X POST ${proxyUrl}/v1/chat/completions \\`,
    `  -H "Authorization: Bearer <your-operator-key>" \\`,
    `  -H "Content-Type: application/json" \\`,
    `  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'`,
  ].join("\n");
}

function MissingProxyUrlNotice(): ReactElement {
  return (
    <Card
      className="border-warning/30 bg-warning/10"
      data-testid="proxy-connection-banner-missing"
    >
      <CardContent className="flex items-start gap-3 py-4 text-sm text-warning">
        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
        <div>
          <p className="font-medium text-foreground">Proxy URL not configured</p>
          <p className="text-xs text-foreground/70">
            The dashboard was provisioned without{" "}
            <code className="font-mono">LLMTRACE_PROXY_URL</code> set.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}

interface ProxyUrlRowProps {
  proxyUrl: string;
  copied: boolean;
  onCopy: () => void;
}

function ProxyUrlRow({ proxyUrl, copied, onCopy }: ProxyUrlRowProps): ReactElement {
  return (
    <div className="space-y-1">
      <p className="text-xs font-medium text-muted-foreground">Proxy URL</p>
      <div className="flex items-center gap-2 rounded-md border bg-background p-2">
        <code
          className="flex-1 break-all font-mono text-sm"
          data-testid="proxy-url-value"
        >
          {proxyUrl}
        </code>
        <Button
          size="icon"
          variant="ghost"
          className="h-8 w-8"
          aria-label="Copy proxy URL"
          data-testid="copy-proxy-url-button"
          onClick={onCopy}
        >
          {copied ? (
            <Check className="h-4 w-4 text-success" />
          ) : (
            <Copy className="h-4 w-4" />
          )}
        </Button>
      </div>
    </div>
  );
}

interface ProxyCurlBlockProps {
  curl: string;
  copied: boolean;
  onCopy: () => void;
}

function ProxyCurlBlock({ curl, copied, onCopy }: ProxyCurlBlockProps): ReactElement {
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between">
        <p className="text-xs font-medium text-muted-foreground">Example request</p>
        <Button
          size="sm"
          variant="ghost"
          className="h-7 text-xs"
          aria-label="Copy curl example"
          data-testid="copy-proxy-curl-button"
          onClick={onCopy}
        >
          {copied ? (
            <Check className="mr-1 h-3 w-3 text-success" />
          ) : (
            <Copy className="mr-1 h-3 w-3" />
          )}
          {copied ? "Copied" : "Copy"}
        </Button>
      </div>
      <pre
        className="overflow-x-auto rounded-md border bg-background p-3 text-xs"
        data-testid="proxy-curl-example"
      >
        <code className="font-mono">{curl}</code>
      </pre>
    </div>
  );
}

function useCopyFlag(): [boolean, () => void] {
  const [copied, setCopied] = useState<boolean>(false);
  const trigger = (): void => {
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return [copied, trigger];
}

export function ProxyConnectionBannerClient({
  proxyUrl,
}: ProxyConnectionBannerClientProps): ReactElement {
  const [copiedUrl, flagUrlCopied] = useCopyFlag();
  const [copiedCurl, flagCurlCopied] = useCopyFlag();

  if (proxyUrl.length === 0) {
    return <MissingProxyUrlNotice />;
  }

  const curl: string = buildCurlExample(proxyUrl);

  const handleCopyUrl = (): void => {
    copyText(proxyUrl);
    flagUrlCopied();
  };

  const handleCopyCurl = (): void => {
    copyText(curl);
    flagCurlCopied();
  };

  return (
    <Card
      className="border-primary/50 bg-primary/5"
      data-testid="proxy-connection-banner"
    >
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <LinkIcon className="h-4 w-4" /> Connection
        </CardTitle>
        <CardDescription>
          Your applications send <code className="font-mono">/v1/*</code> traffic
          to the URL below using an Operator-role API key. Mint and manage keys
          per tenant below.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <ProxyUrlRow proxyUrl={proxyUrl} copied={copiedUrl} onCopy={handleCopyUrl} />
        <ProxyCurlBlock curl={curl} copied={copiedCurl} onCopy={handleCopyCurl} />
      </CardContent>
    </Card>
  );
}
