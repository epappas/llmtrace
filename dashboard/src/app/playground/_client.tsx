"use client";

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
  type ReactElement,
  type RefObject,
} from "react";
import Link from "next/link";
import {
  ArrowUp,
  Bot,
  Loader2,
  MessageSquarePlus,
  Settings2,
  ShieldAlert,
  ShieldCheck,
  User,
  X,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type Role = "system" | "user" | "assistant";

type WireMsg = { role: Role; content: string };

type MsgAction = "allow" | "redact" | "block" | "unknown";

type MsgFinding = {
  rule: string;
  severity: string;
  confidence?: number;
};

type MsgMetadata = {
  loading: boolean;
  traceId: string | null;
  securityScore: number | null; // normalized 0..1
  action: MsgAction;
  findings: MsgFinding[];
  latencyMs: number | null;
  promptTokens: number | null;
  completionTokens: number | null;
  blocked: boolean;
  blockedReason: string | null;
};

type ChatMessage = {
  id: string;
  role: Exclude<Role, "system">;
  content: string;
  model: string | null;
  createdAt: number;
  metadata: MsgMetadata;
};

type Settings = {
  model: string;
  customModel: string;
  temperature: number;
  systemPrompt: string;
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_MODELS: readonly string[] = [
  "gpt-4o-mini",
  "gpt-4o",
  "claude-3-5-sonnet-latest",
  "claude-3-5-haiku-latest",
  "gpt-4-turbo",
];

const SUGGESTIONS: readonly string[] = [
  "Smoke test the proxy",
  "Test prompt injection detection",
  "Anthropic vs OpenAI",
];

const TEXTAREA_LINE_PX = 24;
const TEXTAREA_MAX_LINES = 6;

// ---------------------------------------------------------------------------
// Backend shapes (subset we touch). The real TraceEvent lives in `lib/api.ts`
// but we copy a thin local view so this module stays self-contained.
// ---------------------------------------------------------------------------

type RawFinding = {
  finding_type?: string;
  severity?: string;
  confidence?: number;
  description?: string;
  metadata?: Record<string, string>;
};

type RawSpan = {
  security_score?: number;
  security_findings?: RawFinding[];
  duration_ms?: number | null;
  latency_ms?: number | null;
  prompt_tokens?: number | null;
  completion_tokens?: number | null;
  tags?: Record<string, string>;
};

type RawTrace = {
  trace_id?: string;
  spans?: RawSpan[];
};

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

function emptyMetadata(traceId: string | null): MsgMetadata {
  return {
    loading: traceId != null,
    traceId,
    securityScore: null,
    action: "unknown",
    findings: [],
    latencyMs: null,
    promptTokens: null,
    completionTokens: null,
    blocked: false,
    blockedReason: null,
  };
}

function deriveAction(_score: number, findings: RawFinding[], spanTags: Record<string, string>): MsgAction {
  // Prefer an explicit enforcement signal recorded on the span. The proxy
  // stamps the chosen action there (see crates/llmtrace-proxy enforcement).
  const tagged = spanTags["enforcement_action"] ?? spanTags["action"];
  if (tagged === "block" || tagged === "redact" || tagged === "allow") return tagged;
  // Otherwise consult finding metadata. Highest-severity wins ("block" > "redact" > "allow").
  let best: MsgAction = "unknown";
  const rank: Record<MsgAction, number> = { unknown: 0, allow: 1, redact: 2, block: 3 };
  for (const f of findings) {
    const a = f.metadata?.["recommended_action"];
    if (a === "block" || a === "redact" || a === "allow") {
      if (rank[a] > rank[best]) best = a;
    }
  }
  if (best !== "unknown") return best;
  // If we received a 2xx response, the proxy allowed the request through.
  // The score on its own is informational and must not flip the chip to
  // "block" or "redact" without an explicit enforcement signal.
  return "allow";
}

function deriveMetadata(raw: RawTrace, traceId: string): MsgMetadata {
  const spans = raw.spans ?? [];
  const scoresU8 = spans.map((s) => s.security_score ?? 0);
  const maxU8 = scoresU8.length > 0 ? Math.max(...scoresU8) : 0;
  const normScore = Math.max(0, Math.min(1, maxU8 / 100));
  const findingsRaw: RawFinding[] = spans.flatMap((s) => s.security_findings ?? []);
  const findings: MsgFinding[] = findingsRaw.map((f) => ({
    rule: f.finding_type ?? "unknown",
    severity: f.severity ?? "info",
    confidence: f.confidence,
  }));
  const mergedTags: Record<string, string> = spans.reduce<Record<string, string>>(
    (acc, s) => ({ ...acc, ...(s.tags ?? {}) }),
    {},
  );
  const latencyMs = spans.reduce<number | null>((acc, s) => {
    const v = s.duration_ms ?? s.latency_ms ?? null;
    if (v == null) return acc;
    return (acc ?? 0) + v;
  }, null);
  const promptTokens = spans.reduce<number | null>((acc, s) => {
    if (s.prompt_tokens == null) return acc;
    return (acc ?? 0) + s.prompt_tokens;
  }, null);
  const completionTokens = spans.reduce<number | null>((acc, s) => {
    if (s.completion_tokens == null) return acc;
    return (acc ?? 0) + s.completion_tokens;
  }, null);
  return {
    loading: false,
    traceId,
    securityScore: normScore,
    action: deriveAction(normScore, findingsRaw, mergedTags),
    findings,
    latencyMs,
    promptTokens,
    completionTokens,
    blocked: false,
    blockedReason: null,
  };
}

function blockedMetadata(
  traceId: string | null,
  reason: string,
  findings: MsgFinding[],
): MsgMetadata {
  return {
    loading: false,
    traceId,
    securityScore: 1,
    action: "block",
    findings,
    latencyMs: null,
    promptTokens: null,
    completionTokens: null,
    blocked: true,
    blockedReason: reason,
  };
}

function scoreTone(score: number | null): { label: string; cls: string } {
  if (score == null) return { label: "Score —", cls: "bg-muted text-foreground" };
  const pct = Math.round(score * 100);
  if (score < 0.3) {
    return {
      label: `Score ${pct}`,
      cls: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30",
    };
  }
  if (score <= 0.7) {
    return {
      label: `Score ${pct}`,
      cls: "bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30",
    };
  }
  return {
    label: `Score ${pct}`,
    cls: "bg-red-500/15 text-red-700 dark:text-red-300 border-red-500/30",
  };
}

function actionTone(action: MsgAction): { label: string; cls: string } {
  switch (action) {
    case "allow":
      return {
        label: "Allow",
        cls: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30",
      };
    case "redact":
      return {
        label: "Redact",
        cls: "bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30",
      };
    case "block":
      return {
        label: "Block",
        cls: "bg-red-500/15 text-red-700 dark:text-red-300 border-red-500/30",
      };
    default:
      return { label: "Action —", cls: "bg-muted text-foreground border-border" };
  }
}

function relativeTime(ts: number, now: number): string {
  const diff = Math.max(0, now - ts);
  if (diff < 5_000) return "just now";
  if (diff < 60_000) return `${Math.floor(diff / 1000)}s ago`;
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  return `${Math.floor(diff / 3_600_000)}h ago`;
}

function parseBlockedBody(text: string): { reason: string; findings: MsgFinding[] } {
  try {
    const parsed = JSON.parse(text) as {
      action?: string;
      reason?: string;
      message?: string;
      findings?: RawFinding[];
    };
    if (parsed.action !== "block") return { reason: "", findings: [] };
    const findings: MsgFinding[] = (parsed.findings ?? []).map((f) => ({
      rule: f.finding_type ?? "unknown",
      severity: f.severity ?? "info",
      confidence: f.confidence,
    }));
    return {
      reason: parsed.reason ?? parsed.message ?? "Blocked by LLMTrace policy",
      findings,
    };
  } catch {
    return { reason: "", findings: [] };
  }
}

function newMessageId(): string {
  return `m_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

// ---------------------------------------------------------------------------
// Network — POST chat completion
// ---------------------------------------------------------------------------

type SendPayload = {
  systemPrompt: string;
  history: ChatMessage[];
  draft: string;
  model: string;
  temperature: number;
};

function buildWirePayload(
  args: SendPayload,
): { model: string; temperature: number; messages: WireMsg[] } {
  const trimmedSystem = args.systemPrompt.trim();
  const prefix: WireMsg[] = trimmedSystem ? [{ role: "system", content: trimmedSystem }] : [];
  const prior: WireMsg[] = args.history.map((m) => ({ role: m.role, content: m.content }));
  return {
    model: args.model,
    temperature: args.temperature,
    messages: [...prefix, ...prior, { role: "user", content: args.draft }],
  };
}

type SendResult =
  | { kind: "ok"; assistant: string; traceId: string | null }
  | { kind: "blocked"; reason: string; findings: MsgFinding[]; traceId: string | null }
  | { kind: "err"; error: string; traceId: string | null };

async function postChat(args: SendPayload): Promise<SendResult> {
  const res = await fetch("/api/proxy/v1/chat/completions", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(buildWirePayload(args)),
  });
  const traceId = res.headers.get("x-llmtrace-trace-id");
  const text = await res.text();
  if (!res.ok) {
    const { reason, findings } = parseBlockedBody(text);
    if (reason || findings.length > 0) {
      return { kind: "blocked", reason: reason || "Blocked by LLMTrace", findings, traceId };
    }
    return { kind: "err", error: `HTTP ${res.status}: ${text.slice(0, 500)}`, traceId };
  }
  try {
    const body = JSON.parse(text) as { choices?: Array<{ message?: { content?: unknown } }> };
    const content = body?.choices?.[0]?.message?.content;
    return {
      kind: "ok",
      assistant: typeof content === "string" ? content : String(content ?? ""),
      traceId,
    };
  } catch {
    return { kind: "err", error: "Invalid JSON response", traceId };
  }
}

async function fetchTrace(traceId: string): Promise<RawTrace | null> {
  try {
    const res = await fetch(`/api/proxy/traces/${traceId}`, { cache: "no-store" });
    if (!res.ok) return null;
    return (await res.json()) as RawTrace;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Auto-grow textarea hook
// ---------------------------------------------------------------------------

function useAutoGrow(value: string): RefObject<HTMLTextAreaElement | null> {
  const ref = useRef<HTMLTextAreaElement | null>(null);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    el.style.height = "auto";
    const max = TEXTAREA_LINE_PX * TEXTAREA_MAX_LINES;
    el.style.height = `${Math.min(el.scrollHeight, max)}px`;
  }, [value]);
  return ref;
}

// ---------------------------------------------------------------------------
// Root component
// ---------------------------------------------------------------------------

export default function PlaygroundClient(): ReactElement {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [draft, setDraft] = useState<string>("");
  const [pending, setPending] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [settingsOpen, setSettingsOpen] = useState<boolean>(false);
  const [settings, setSettings] = useState<Settings>({
    model: "gpt-4o-mini",
    customModel: "",
    temperature: 0.7,
    systemPrompt: "",
  });

  const effectiveModel = useMemo(
    () => (settings.customModel.trim() !== "" ? settings.customModel.trim() : settings.model),
    [settings.customModel, settings.model],
  );

  const attachTraceMeta = useCallback((messageIds: string[], traceId: string): void => {
    void fetchTrace(traceId).then((raw) => {
      if (!raw) {
        setMessages((prev) =>
          prev.map((m) =>
            messageIds.includes(m.id) ? { ...m, metadata: { ...m.metadata, loading: false } } : m,
          ),
        );
        return;
      }
      const derived = deriveMetadata(raw, traceId);
      setMessages((prev) =>
        prev.map((m) => (messageIds.includes(m.id) ? { ...m, metadata: derived } : m)),
      );
    });
  }, []);

  const handleResult = useCallback(
    (userId: string, model: string, result: SendResult): void => {
      if (result.kind === "blocked") {
        const meta = blockedMetadata(result.traceId, result.reason, result.findings);
        setMessages((prev) => prev.map((m) => (m.id === userId ? { ...m, metadata: meta } : m)));
        return;
      }
      if (result.kind === "err") {
        setError(result.error);
        setMessages((prev) =>
          prev.map((m) =>
            m.id === userId ? { ...m, metadata: emptyMetadata(result.traceId) } : m,
          ),
        );
        return;
      }
      const assistantId = newMessageId();
      const assistant: ChatMessage = {
        id: assistantId,
        role: "assistant",
        content: result.assistant,
        model,
        createdAt: Date.now(),
        metadata: emptyMetadata(result.traceId),
      };
      setMessages((prev) => [
        ...prev.map((m) =>
          m.id === userId ? { ...m, metadata: emptyMetadata(result.traceId) } : m,
        ),
        assistant,
      ]);
      if (result.traceId) attachTraceMeta([userId, assistantId], result.traceId);
    },
    [attachTraceMeta],
  );

  const send = useCallback(async (): Promise<void> => {
    const trimmed = draft.trim();
    if (pending || trimmed === "") return;
    setPending(true);
    setError(null);
    const userId = newMessageId();
    const userMsg: ChatMessage = {
      id: userId,
      role: "user",
      content: trimmed,
      model: effectiveModel,
      createdAt: Date.now(),
      metadata: emptyMetadata(null),
    };
    const history = messages;
    setMessages((prev) => [...prev, userMsg]);
    setDraft("");
    try {
      const result = await postChat({
        systemPrompt: settings.systemPrompt,
        history,
        draft: trimmed,
        model: effectiveModel,
        temperature: settings.temperature,
      });
      handleResult(userId, effectiveModel, result);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setPending(false);
    }
  }, [draft, pending, messages, effectiveModel, settings, handleResult]);

  const onKeyDown = useCallback(
    (event: KeyboardEvent<HTMLTextAreaElement>): void => {
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
        event.preventDefault();
        void send();
      }
    },
    [send],
  );

  const clear = useCallback((): void => {
    setMessages([]);
    setError(null);
  }, []);

  const pickSuggestion = useCallback((s: string): void => setDraft(s), []);

  return (
    <div className="flex h-[calc(100vh-7rem)] flex-col">
      <PlaygroundHeader
        model={effectiveModel}
        onClear={clear}
        onOpenSettings={() => setSettingsOpen(true)}
        canClear={messages.length > 0 && !pending}
      />
      <div className="flex-1 overflow-y-auto" data-testid="playground-scroll">
        <div className="mx-auto w-full max-w-3xl px-4 py-6">
          {messages.length === 0 ? (
            <EmptyState onPick={pickSuggestion} />
          ) : (
            <Transcript messages={messages} />
          )}
          {error && (
            <p
              className="mt-4 rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-xs text-destructive"
              data-testid="playground-error"
            >
              {error}
            </p>
          )}
        </div>
      </div>
      <Composer
        draft={draft}
        setDraft={setDraft}
        onKeyDown={onKeyDown}
        onSend={() => void send()}
        pending={pending}
      />
      <SettingsDrawer
        open={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        settings={settings}
        setSettings={setSettings}
        disabled={pending}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

function PlaygroundHeader(props: {
  model: string;
  onClear: () => void;
  onOpenSettings: () => void;
  canClear: boolean;
}): ReactElement {
  return (
    <div className="flex items-center justify-between border-b bg-background/80 px-4 py-3 backdrop-blur">
      <div className="flex items-center gap-3">
        <h1 className="text-lg font-semibold tracking-tight">Playground</h1>
        <Badge variant="outline" data-testid="playground-header-model">
          {props.model}
        </Badge>
      </div>
      <div className="flex items-center gap-2">
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={props.onClear}
          disabled={!props.canClear}
          data-testid="playground-clear"
        >
          Clear
        </Button>
        <Button
          type="button"
          variant="ghost"
          size="icon"
          onClick={props.onOpenSettings}
          aria-label="Open settings"
          data-testid="playground-open-settings"
        >
          <Settings2 className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Empty state
// ---------------------------------------------------------------------------

function EmptyState(props: { onPick: (s: string) => void }): ReactElement {
  return (
    <div
      className="flex flex-col items-center justify-center gap-6 py-16 text-center"
      data-testid="playground-empty"
    >
      <div className="rounded-full border bg-card p-4 text-muted-foreground">
        <MessageSquarePlus className="h-6 w-6" />
      </div>
      <div className="space-y-1">
        <p className="text-base font-medium">Start a conversation</p>
        <p className="text-xs text-muted-foreground">
          Messages route through your LLMTrace proxy. Every turn produces a trace.
        </p>
      </div>
      <div className="flex flex-wrap items-center justify-center gap-2">
        {SUGGESTIONS.map((s) => (
          <button
            key={s}
            type="button"
            onClick={() => props.onPick(s)}
            data-testid="playground-suggestion"
            className="rounded-full border bg-card px-3 py-1.5 text-xs text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
          >
            {s}
          </button>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Transcript
// ---------------------------------------------------------------------------

function Transcript(props: { messages: ChatMessage[] }): ReactElement {
  const [now, setNow] = useState<number>(() => Date.now());
  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), 30_000);
    return () => window.clearInterval(id);
  }, []);
  return (
    <div className="space-y-4" data-testid="playground-transcript">
      {props.messages.map((m) => (
        <MessageRow key={m.id} msg={m} now={now} />
      ))}
    </div>
  );
}

function MessageRow(props: { msg: ChatMessage; now: number }): ReactElement {
  const { msg, now } = props;
  const isUser = msg.role === "user";
  return (
    <div
      className={`flex gap-3 ${isUser ? "flex-row-reverse" : "flex-row"}`}
      data-testid={`playground-msg-${msg.role}`}
    >
      <Avatar role={msg.role} />
      <div className={`flex max-w-[80%] flex-col gap-1 ${isUser ? "items-end" : "items-start"}`}>
        <Bubble msg={msg} isUser={isUser} />
        <MetaRow msg={msg} now={now} />
      </div>
    </div>
  );
}

function Avatar(props: { role: "user" | "assistant" }): ReactElement {
  const Icon = props.role === "user" ? User : Bot;
  return (
    <div className="mt-1 flex h-7 w-7 shrink-0 items-center justify-center rounded-full border bg-card text-muted-foreground">
      <Icon className="h-3.5 w-3.5" />
    </div>
  );
}

function Bubble(props: { msg: ChatMessage; isUser: boolean }): ReactElement {
  const tone = props.isUser ? "bg-primary/10 border-primary/20" : "bg-card border-border";
  return (
    <div
      className={`rounded-2xl border px-4 py-2.5 text-sm leading-relaxed whitespace-pre-wrap ${tone}`}
    >
      {props.msg.content}
    </div>
  );
}

function MetaRow(props: { msg: ChatMessage; now: number }): ReactElement {
  const { msg, now } = props;
  const meta = msg.metadata;
  const isUser = msg.role === "user";
  return (
    <div
      className={`flex flex-wrap items-center gap-1.5 text-[11px] text-muted-foreground ${
        isUser ? "justify-end" : "justify-start"
      }`}
    >
      <span>{relativeTime(msg.createdAt, now)}</span>
      {msg.model && (
        <>
          <span>·</span>
          <span>{msg.model}</span>
        </>
      )}
      {!isUser && meta.latencyMs != null && (
        <>
          <span>·</span>
          <span>{(meta.latencyMs / 1000).toFixed(1)}s</span>
        </>
      )}
      {!isUser && meta.completionTokens != null && (
        <>
          <span>·</span>
          <span>{meta.completionTokens}t</span>
        </>
      )}
      <MetadataPills msg={msg} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Metadata pills
// ---------------------------------------------------------------------------

function MetadataPills(props: { msg: ChatMessage }): ReactElement | null {
  const meta = props.msg.metadata;
  if (meta.loading) {
    return (
      <span
        className="inline-flex items-center gap-1 rounded-full border border-border bg-muted/40 px-2 py-0.5 text-[10px]"
        data-testid="playground-meta-loading"
      >
        <Loader2 className="h-2.5 w-2.5 animate-spin" />
        analyzing
      </span>
    );
  }
  if (meta.blocked) return <BlockedPill msg={props.msg} />;
  if (meta.securityScore == null && !meta.traceId) return null;
  return (
    <>
      {meta.securityScore != null && <ScorePill msg={props.msg} />}
      {meta.action !== "unknown" && <ActionPill action={meta.action} />}
      {meta.traceId && (
        <Link
          href={`/traces/${meta.traceId}`}
          className="inline-flex items-center rounded-full border border-border bg-card px-2 py-0.5 text-[10px] text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
          data-testid="playground-meta-trace"
        >
          {"Trace →"}
        </Link>
      )}
    </>
  );
}

function ScorePill(props: { msg: ChatMessage }): ReactElement {
  const [open, setOpen] = useState<boolean>(false);
  const meta = props.msg.metadata;
  const tone = scoreTone(meta.securityScore);
  return (
    <span className="relative inline-flex">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-medium ${tone.cls}`}
        data-testid="playground-meta-score"
        aria-expanded={open}
      >
        <ShieldCheck className="h-2.5 w-2.5" />
        {tone.label}
      </button>
      {open && (
        <span
          className="absolute z-10 mt-6 max-w-xs rounded-md border bg-popover p-2 text-[11px] text-popover-foreground shadow-md"
          data-testid="playground-meta-score-popover"
          style={{ top: "100%" }}
        >
          {meta.findings.length === 0 ? (
            <span className="text-muted-foreground">No findings.</span>
          ) : (
            <ul className="space-y-1">
              {meta.findings.map((f, i) => (
                <li key={i} className="flex items-center gap-1.5">
                  <span className="font-medium">{f.severity}</span>
                  <span>{f.rule}</span>
                  {f.confidence != null && (
                    <span className="text-muted-foreground">
                      ({Math.round((f.confidence ?? 0) * 100)}%)
                    </span>
                  )}
                </li>
              ))}
            </ul>
          )}
        </span>
      )}
    </span>
  );
}

function ActionPill(props: { action: MsgAction }): ReactElement {
  const tone = actionTone(props.action);
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-medium ${tone.cls}`}
      data-testid="playground-meta-action"
    >
      {tone.label}
    </span>
  );
}

function BlockedPill(props: { msg: ChatMessage }): ReactElement {
  const meta = props.msg.metadata;
  return (
    <span className="flex flex-col items-end gap-1">
      <span
        className="inline-flex items-center gap-1 rounded-full border border-red-500/30 bg-red-500/15 px-2 py-0.5 text-[10px] font-medium text-red-700 dark:text-red-300"
        data-testid="playground-meta-blocked"
      >
        <ShieldAlert className="h-2.5 w-2.5" />
        Blocked by LLMTrace
      </span>
      {meta.blockedReason && (
        <span
          className="max-w-xs text-right text-[10px] text-muted-foreground"
          data-testid="playground-meta-blocked-reason"
        >
          {meta.blockedReason}
        </span>
      )}
      {meta.findings.length > 0 && (
        <span className="text-right text-[10px] text-muted-foreground">
          {meta.findings.map((f) => f.rule).join(", ")}
        </span>
      )}
      {meta.traceId && (
        <Link
          href={`/traces/${meta.traceId}`}
          className="text-[10px] text-muted-foreground underline-offset-2 hover:underline"
          data-testid="playground-meta-trace"
        >
          {"Trace →"}
        </Link>
      )}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Composer (input + send)
// ---------------------------------------------------------------------------

function Composer(props: {
  draft: string;
  setDraft: (v: string) => void;
  onKeyDown: (e: KeyboardEvent<HTMLTextAreaElement>) => void;
  onSend: () => void;
  pending: boolean;
}): ReactElement {
  const ref = useAutoGrow(props.draft);
  const disabled = props.pending || props.draft.trim() === "";
  return (
    <div className="border-t bg-background/80 px-4 py-3 backdrop-blur">
      <div className="mx-auto flex w-full max-w-3xl items-end gap-2 rounded-2xl border bg-card px-3 py-2 focus-within:ring-2 focus-within:ring-primary/30">
        <textarea
          ref={ref}
          data-testid="playground-input"
          value={props.draft}
          onChange={(e) => props.setDraft(e.target.value)}
          onKeyDown={props.onKeyDown}
          disabled={props.pending}
          rows={1}
          placeholder="Send a message. Cmd/Ctrl+Enter to send, Enter for newline."
          className="flex-1 resize-none border-0 bg-transparent px-1 py-1.5 text-sm leading-6 focus:outline-none disabled:cursor-not-allowed"
          style={{ maxHeight: `${TEXTAREA_LINE_PX * TEXTAREA_MAX_LINES}px` }}
        />
        <Button
          type="button"
          size="icon"
          onClick={props.onSend}
          disabled={disabled}
          aria-label="Send message"
          data-testid="playground-send"
          className="rounded-full"
        >
          {props.pending ? (
            <Loader2 className="h-4 w-4 animate-spin" data-testid="playground-pending" />
          ) : (
            <ArrowUp className="h-4 w-4" />
          )}
        </Button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Settings drawer
// ---------------------------------------------------------------------------

function SettingsDrawer(props: {
  open: boolean;
  onClose: () => void;
  settings: Settings;
  setSettings: (next: Settings) => void;
  disabled: boolean;
}): ReactElement {
  // Mount unconditionally so transitions animate on both open and close.
  const visible = props.open;
  return (
    <>
      <button
        type="button"
        aria-hidden={!visible}
        tabIndex={-1}
        onClick={props.onClose}
        className={`fixed inset-0 z-40 bg-black/40 transition-opacity ${
          visible ? "opacity-100" : "pointer-events-none opacity-0"
        }`}
      />
      <aside
        role="dialog"
        aria-label="Playground settings"
        aria-modal="true"
        data-testid="playground-settings-drawer"
        data-open={visible ? "true" : "false"}
        className={`fixed inset-y-0 right-0 z-50 flex w-full max-w-sm flex-col border-l bg-background shadow-xl transition-transform duration-200 ${
          visible ? "translate-x-0" : "translate-x-full"
        }`}
      >
        <div className="flex items-center justify-between border-b px-4 py-3">
          <h2 className="text-sm font-semibold">Settings</h2>
          <Button
            type="button"
            variant="ghost"
            size="icon"
            onClick={props.onClose}
            aria-label="Close settings"
            data-testid="playground-close-settings"
          >
            <X className="h-4 w-4" />
          </Button>
        </div>
        <div className="flex-1 overflow-y-auto px-4 py-4">
          <SettingsForm
            settings={props.settings}
            setSettings={props.setSettings}
            disabled={props.disabled}
          />
        </div>
      </aside>
    </>
  );
}

function SettingsForm(props: {
  settings: Settings;
  setSettings: (next: Settings) => void;
  disabled: boolean;
}): ReactElement {
  const s = props.settings;
  const update = (patch: Partial<Settings>): void => props.setSettings({ ...s, ...patch });
  return (
    <div className="space-y-5">
      <label className="flex flex-col gap-1.5 text-xs">
        <span className="font-medium text-foreground">Model</span>
        <select
          data-testid="playground-model"
          value={s.model}
          onChange={(e) => update({ model: e.target.value })}
          disabled={props.disabled}
          className="rounded-md border bg-background px-2 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
        >
          {DEFAULT_MODELS.map((m) => (
            <option key={m} value={m}>
              {m}
            </option>
          ))}
        </select>
      </label>
      <label className="flex flex-col gap-1.5 text-xs">
        <span className="font-medium text-foreground">Custom model (overrides)</span>
        <input
          type="text"
          data-testid="playground-custom-model"
          value={s.customModel}
          onChange={(e) => update({ customModel: e.target.value })}
          disabled={props.disabled}
          placeholder="e.g. my-org/my-model"
          className="rounded-md border bg-background px-2 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
        />
      </label>
      <label className="flex flex-col gap-1.5 text-xs">
        <span className="font-medium text-foreground">
          Temperature: {s.temperature.toFixed(2)}
        </span>
        <input
          type="range"
          min={0}
          max={2}
          step={0.05}
          data-testid="playground-temperature"
          value={s.temperature}
          onChange={(e) => update({ temperature: Number(e.target.value) })}
          disabled={props.disabled}
          className="w-full"
        />
      </label>
      <label className="flex flex-col gap-1.5 text-xs">
        <span className="font-medium text-foreground">System prompt</span>
        <textarea
          data-testid="playground-system-prompt"
          value={s.systemPrompt}
          onChange={(e) => update({ systemPrompt: e.target.value })}
          disabled={props.disabled}
          rows={5}
          placeholder="Prepended as a `system` message on every send."
          className="rounded-md border bg-background px-2 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
        />
      </label>
    </div>
  );
}
