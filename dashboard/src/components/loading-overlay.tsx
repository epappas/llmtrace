"use client";

import { Shield, Loader2 } from "lucide-react";

interface LoadingOverlayProps {
  progressPct: number;
  loadedModels?: number;
  totalModels?: number;
}

export function LoadingOverlay({
  progressPct,
  loadedModels,
  totalModels,
}: LoadingOverlayProps) {
  const clamped = Math.max(0, Math.min(100, progressPct));
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/95 backdrop-blur-sm">
      <div className="w-full max-w-lg rounded-xl border bg-card p-8 shadow-xl">
        <div className="mb-4 flex items-center gap-3">
          <div className="relative rounded-lg bg-muted p-2">
            <Shield className="h-6 w-6 text-emerald-600" />
            <Loader2 className="absolute -right-2 -top-2 h-4 w-4 animate-spin text-emerald-600" />
          </div>
          <div>
            <h2 className="text-lg font-semibold">Bootstrapping Security Engines</h2>
            <p className="text-sm text-muted-foreground">
              Proxy is online. ML protections are loading in the background.
            </p>
          </div>
        </div>

        <div className="mb-2 h-2 w-full overflow-hidden rounded-full bg-muted">
          <div
            className="h-full rounded-full bg-emerald-600 transition-all duration-500"
            style={{ width: `${clamped}%` }}
          />
        </div>
        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <span>{clamped}% complete</span>
          {typeof loadedModels === "number" && typeof totalModels === "number" && (
            <span>
              {loadedModels}/{totalModels} models
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
