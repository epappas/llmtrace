"use client";

import { useEffect, useRef, useState } from "react";
import { Sidebar } from "@/components/sidebar";
import { LoadingOverlay } from "@/components/loading-overlay";
import { ReconnectBanner } from "@/components/reconnect-banner";

type LifecyclePhase = "bootstrapping" | "ready" | "reconnecting";

interface HealthPayload {
  status?: string;
  starting?: boolean;
  ml?: {
    status?: string;
    progress_pct?: number;
    loaded_models?: number;
    total_models?: number;
  };
}

interface RetryEntry {
  attempt: number;
  delayMs: number;
  runAt: number;
}

const BOOTSTRAP_POLL_MS = 1500;
const READY_POLL_MS = 3000;
const BACKOFF_BASE_MS = 500;
const BACKOFF_MAX_MS = 15000;

function clampPercent(value: number): number {
  return Math.max(0, Math.min(100, Math.round(value)));
}

function computeBackoffMs(attempt: number): number {
  return Math.min(
    BACKOFF_MAX_MS,
    BACKOFF_BASE_MS * 2 ** Math.max(0, attempt - 1),
  );
}

function isHealthy(payload: HealthPayload): boolean {
  return payload.status === "healthy" || payload.status === "ok";
}

function isInitializing(payload: HealthPayload): boolean {
  return Boolean(payload.starting) || payload.ml?.status === "initializing";
}

function resolveProgress(payload: HealthPayload): number {
  if (typeof payload.ml?.progress_pct === "number") {
    return clampPercent(payload.ml.progress_pct);
  }
  if (
    typeof payload.ml?.loaded_models === "number" &&
    typeof payload.ml?.total_models === "number" &&
    payload.ml.total_models > 0
  ) {
    return clampPercent(
      (payload.ml.loaded_models / payload.ml.total_models) * 100,
    );
  }
  return 0;
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const [phase, setPhase] = useState<LifecyclePhase>("bootstrapping");
  const [bootProgress, setBootProgress] = useState(0);
  const [loadedModels, setLoadedModels] = useState<number | undefined>();
  const [totalModels, setTotalModels] = useState<number | undefined>();
  const [retryAttempt, setRetryAttempt] = useState(0);
  const [retryDelayMs, setRetryDelayMs] = useState<number | undefined>();
  const [nextRetryAt, setNextRetryAt] = useState<number | null>(null);
  const [nowTs, setNowTs] = useState(Date.now());
  const [bannerMessage, setBannerMessage] = useState("Reconnecting to proxy...");

  const reachedReadyRef = useRef(false);
  const retryAttemptRef = useRef(0);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const cancelledRef = useRef(false);
  const retryQueueRef = useRef<RetryEntry[]>([]);

  useEffect(() => {
    const ticker = setInterval(() => setNowTs(Date.now()), 250);
    return () => clearInterval(ticker);
  }, []);

  useEffect(() => {
    cancelledRef.current = false;

    const clearTimer = () => {
      if (timerRef.current) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
      }
    };

    const scheduleCheck = (delayMs: number) => {
      clearTimer();
      timerRef.current = setTimeout(() => {
        if (cancelledRef.current) {
          return;
        }
        if (retryQueueRef.current.length > 0) {
          retryQueueRef.current.shift();
        }
        void checkHealth();
      }, delayMs);
    };

    const schedulePoll = (delayMs: number) => {
      setNextRetryAt(null);
      setRetryDelayMs(undefined);
      scheduleCheck(delayMs);
    };

    const scheduleRetry = (delayMs: number, attempt: number) => {
      const runAt = Date.now() + delayMs;
      retryQueueRef.current = [{ attempt, delayMs, runAt }];
      setNextRetryAt(runAt);
      setRetryDelayMs(delayMs);
      scheduleCheck(delayMs);
    };

    const moveToReady = () => {
      reachedReadyRef.current = true;
      retryAttemptRef.current = 0;
      retryQueueRef.current = [];
      setPhase("ready");
      setRetryAttempt(0);
      setNextRetryAt(null);
      setRetryDelayMs(undefined);
      schedulePoll(READY_POLL_MS);
    };

    const moveToInitializing = (payload: HealthPayload) => {
      const progress = resolveProgress(payload);
      setBootProgress(progress);
      setLoadedModels(payload.ml?.loaded_models);
      setTotalModels(payload.ml?.total_models);
      retryAttemptRef.current = 0;
      setRetryAttempt(0);
      setNextRetryAt(null);
      setRetryDelayMs(undefined);
      retryQueueRef.current = [];

      if (reachedReadyRef.current) {
        setPhase("reconnecting");
        setBannerMessage(
          "Proxy is restarting. Security engines are reloading...",
        );
      } else {
        setPhase("bootstrapping");
      }
      schedulePoll(BOOTSTRAP_POLL_MS);
    };

    const moveToRetrying = () => {
      const nextAttempt = retryAttemptRef.current + 1;
      retryAttemptRef.current = nextAttempt;
      const delayMs = computeBackoffMs(nextAttempt);

      setRetryAttempt(nextAttempt);
      setBannerMessage("Reconnecting to proxy...");

      if (reachedReadyRef.current) {
        setPhase("reconnecting");
      } else {
        setPhase("bootstrapping");
      }

      scheduleRetry(delayMs, nextAttempt);
    };

    const checkHealth = async () => {
      try {
        const response = await fetch("/health", { cache: "no-store" });
        if (!response.ok) {
          throw new Error(`Health status ${response.status}`);
        }

        const payload = (await response.json()) as HealthPayload;
        const healthy = isHealthy(payload);
        const initializing = isInitializing(payload);

        if (healthy && !initializing) {
          moveToReady();
          return;
        }

        if (initializing) {
          moveToInitializing(payload);
          return;
        }

        throw new Error("Proxy is not ready");
      } catch {
        moveToRetrying();
      }
    };

    void checkHealth();

    return () => {
      cancelledRef.current = true;
      clearTimer();
      retryQueueRef.current = [];
    };
  }, []);

  const retryInSeconds =
    nextRetryAt === null ? 0 : Math.max(0, Math.ceil((nextRetryAt - nowTs) / 1000));
  const showReconnectBanner = phase === "reconnecting" || retryAttempt > 0;

  return (
    <div className="flex h-screen">
      <Sidebar />
      <main className="flex-1 overflow-y-auto">
        {showReconnectBanner && (
          <ReconnectBanner
            attempt={retryAttempt > 0 ? retryAttempt : undefined}
            retryInSeconds={retryAttempt > 0 ? retryInSeconds : undefined}
            retryDelayMs={retryDelayMs}
            message={bannerMessage}
          />
        )}
        <div className="container py-6">{children}</div>
      </main>
      {phase === "bootstrapping" && (
        <div data-testid="proxy-loading-overlay">
          <LoadingOverlay
            progressPct={bootProgress}
            loadedModels={loadedModels}
            totalModels={totalModels}
          />
        </div>
      )}
    </div>
  );
}
