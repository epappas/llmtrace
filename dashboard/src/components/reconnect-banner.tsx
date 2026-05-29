"use client";

import { AlertTriangle, RefreshCw } from "lucide-react";

interface ReconnectBannerProps {
  attempt?: number;
  retryInSeconds?: number;
  retryDelayMs?: number;
  message: string;
}

export function ReconnectBanner({
  attempt,
  retryInSeconds,
  retryDelayMs,
  message,
}: ReconnectBannerProps) {
  return (
    <div
      data-testid="proxy-reconnect-banner"
      className="sticky top-0 z-40 border-b border-warning/30 bg-warning/10 px-4 py-2 text-warning"
    >
      <div className="flex items-center gap-3 text-sm">
        <AlertTriangle className="h-4 w-4 shrink-0" />
        <span className="font-medium text-foreground">{message}</span>
        {typeof attempt === "number" && (
          <span data-testid="proxy-retry-attempt" className="text-foreground/70">
            Attempt {attempt}
          </span>
        )}
        {typeof retryInSeconds === "number" && (
          <span
            data-testid="proxy-retry-countdown"
            className="ml-auto inline-flex items-center gap-1 text-xs"
          >
            <RefreshCw className="h-3 w-3" />
            Retrying in {retryInSeconds}s
          </span>
        )}
        {typeof retryDelayMs === "number" && (
          <span data-testid="proxy-retry-delay-ms" className="text-xs text-foreground/70">
            Backoff {retryDelayMs}ms
          </span>
        )}
      </div>
    </div>
  );
}
