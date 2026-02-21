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
      className="sticky top-0 z-40 border-b border-amber-300 bg-amber-50 px-4 py-2 text-amber-900"
    >
      <div className="flex items-center gap-3 text-sm">
        <AlertTriangle className="h-4 w-4 shrink-0" />
        <span className="font-medium">{message}</span>
        {typeof attempt === "number" && (
          <span data-testid="proxy-retry-attempt" className="text-amber-800/90">
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
          <span data-testid="proxy-retry-delay-ms" className="text-xs text-amber-800/90">
            Backoff {retryDelayMs}ms
          </span>
        )}
      </div>
    </div>
  );
}
