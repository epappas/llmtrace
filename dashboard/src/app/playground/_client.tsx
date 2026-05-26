"use client";

import { useState, type ReactElement, type KeyboardEvent } from "react";
import Link from "next/link";
import { Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

type Role = "system" | "user" | "assistant";
type Msg = { role: Role; content: string };

const DEFAULT_MODELS: readonly string[] = [
  "gpt-4o-mini",
  "gpt-4o",
  "claude-3-5-sonnet-latest",
  "claude-3-5-haiku-latest",
  "gpt-4-turbo",
];

type SendArgs = {
  systemPrompt: string;
  messages: Msg[];
  draft: string;
  model: string;
  temperature: number;
};

type SendResult =
  | { kind: "ok"; assistant: string; traceId: string | null }
  | { kind: "err"; error: string; traceId: string | null };

function buildPayload(args: SendArgs): { model: string; temperature: number; messages: Msg[] } {
  const trimmedSystem = args.systemPrompt.trim();
  const prefix: Msg[] = trimmedSystem ? [{ role: "system", content: trimmedSystem }] : [];
  const all: Msg[] = [...prefix, ...args.messages, { role: "user", content: args.draft }];
  return { model: args.model, temperature: args.temperature, messages: all };
}

async function postChat(args: SendArgs): Promise<SendResult> {
  const res = await fetch("/api/proxy/v1/chat/completions", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(buildPayload(args)),
  });
  const traceId = res.headers.get("x-llmtrace-trace-id");
  if (!res.ok) {
    const body = await res.text();
    return { kind: "err", error: `HTTP ${res.status}: ${body.slice(0, 500)}`, traceId };
  }
  const body = (await res.json()) as { choices?: Array<{ message?: { content?: unknown } }> };
  const content = body?.choices?.[0]?.message?.content;
  return { kind: "ok", assistant: typeof content === "string" ? content : String(content ?? ""), traceId };
}

export default function PlaygroundClient(): ReactElement {
  const [messages, setMessages] = useState<Msg[]>([]);
  const [draft, setDraft] = useState<string>("");
  const [model, setModel] = useState<string>("gpt-4o-mini");
  const [customModel, setCustomModel] = useState<string>("");
  const [temperature, setTemperature] = useState<number>(0.7);
  const [systemPrompt, setSystemPrompt] = useState<string>("");
  const [pending, setPending] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [lastTraceId, setLastTraceId] = useState<string | null>(null);

  const effectiveModel = customModel.trim() !== "" ? customModel.trim() : model;

  async function send(): Promise<void> {
    if (pending || draft.trim() === "") return;
    setPending(true);
    setError(null);
    const userMsg: Msg = { role: "user", content: draft };
    try {
      const result = await postChat({ systemPrompt, messages, draft, model: effectiveModel, temperature });
      if (result.traceId) setLastTraceId(result.traceId);
      if (result.kind === "err") {
        setError(result.error);
        return;
      }
      setMessages((prev) => [...prev, userMsg, { role: "assistant", content: result.assistant }]);
      setDraft("");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setPending(false);
    }
  }

  function onKeyDown(event: KeyboardEvent<HTMLTextAreaElement>): void {
    if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
      event.preventDefault();
      void send();
    }
  }

  function clear(): void {
    setMessages([]);
    setError(null);
    setLastTraceId(null);
  }

  return (
    <div className="space-y-4">
      <PlaygroundControls
        model={model}
        setModel={setModel}
        customModel={customModel}
        setCustomModel={setCustomModel}
        temperature={temperature}
        setTemperature={setTemperature}
        onClear={clear}
        disabled={pending}
      />
      <SystemPromptField value={systemPrompt} setValue={setSystemPrompt} disabled={pending} />
      <Transcript messages={messages} />
      <StatusRow pending={pending} error={error} traceId={lastTraceId} />
      <InputArea
        draft={draft}
        setDraft={setDraft}
        onKeyDown={onKeyDown}
        onSend={() => void send()}
        disabled={pending}
      />
    </div>
  );
}

type ControlsProps = {
  model: string;
  setModel: (v: string) => void;
  customModel: string;
  setCustomModel: (v: string) => void;
  temperature: number;
  setTemperature: (v: number) => void;
  onClear: () => void;
  disabled: boolean;
};

function PlaygroundControls(props: ControlsProps): ReactElement {
  return (
    <div className="flex flex-wrap items-end gap-3 rounded-md border bg-card p-3">
      <label className="flex flex-col gap-1 text-xs">
        <span className="font-medium text-muted-foreground">Model</span>
        <select
          data-testid="playground-model"
          value={props.model}
          onChange={(e) => props.setModel(e.target.value)}
          disabled={props.disabled}
          className="rounded-md border bg-background px-2 py-1 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
        >
          {DEFAULT_MODELS.map((m) => (
            <option key={m} value={m}>
              {m}
            </option>
          ))}
        </select>
      </label>
      <label className="flex flex-col gap-1 text-xs">
        <span className="font-medium text-muted-foreground">Custom model (overrides)</span>
        <input
          type="text"
          data-testid="playground-custom-model"
          value={props.customModel}
          onChange={(e) => props.setCustomModel(e.target.value)}
          disabled={props.disabled}
          placeholder="e.g. my-org/my-model"
          className="rounded-md border bg-background px-2 py-1 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
        />
      </label>
      <label className="flex flex-col gap-1 text-xs">
        <span className="font-medium text-muted-foreground">
          Temperature: {props.temperature.toFixed(2)}
        </span>
        <input
          type="range"
          min={0}
          max={2}
          step={0.05}
          data-testid="playground-temperature"
          value={props.temperature}
          onChange={(e) => props.setTemperature(Number(e.target.value))}
          disabled={props.disabled}
          className="w-48"
        />
      </label>
      <Button
        type="button"
        variant="outline"
        size="sm"
        onClick={props.onClear}
        disabled={props.disabled}
        data-testid="playground-clear"
      >
        Clear conversation
      </Button>
    </div>
  );
}

function SystemPromptField(props: {
  value: string;
  setValue: (v: string) => void;
  disabled: boolean;
}): ReactElement {
  return (
    <label className="flex flex-col gap-1 text-xs">
      <span className="font-medium text-muted-foreground">System prompt (optional)</span>
      <textarea
        data-testid="playground-system-prompt"
        value={props.value}
        onChange={(e) => props.setValue(e.target.value)}
        disabled={props.disabled}
        rows={2}
        placeholder="Prepended as a `system` message on every send"
        className="rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
      />
    </label>
  );
}

function Transcript(props: { messages: Msg[] }): ReactElement {
  if (props.messages.length === 0) {
    return (
      <Card>
        <CardContent className="p-6 text-sm text-muted-foreground">
          No messages yet. Send a message below to exercise the proxy.
        </CardContent>
      </Card>
    );
  }
  return (
    <div className="space-y-2" data-testid="playground-transcript">
      {props.messages.map((m, i) => (
        <MessageBubble key={i} msg={m} />
      ))}
    </div>
  );
}

function MessageBubble(props: { msg: Msg }): ReactElement {
  const isUser = props.msg.role === "user";
  const align = isUser ? "ml-auto" : "mr-auto";
  const tone = isUser ? "bg-primary text-primary-foreground" : "bg-card";
  return (
    <div
      data-testid={`playground-msg-${props.msg.role}`}
      className={`max-w-[80%] rounded-md border p-3 text-sm whitespace-pre-wrap ${align} ${tone}`}
    >
      <div className="mb-1 text-[10px] font-bold uppercase opacity-70">{props.msg.role}</div>
      {props.msg.content}
    </div>
  );
}

function StatusRow(props: {
  pending: boolean;
  error: string | null;
  traceId: string | null;
}): ReactElement {
  return (
    <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
      {props.pending && (
        <span className="flex items-center gap-1" data-testid="playground-pending">
          <Loader2 className="h-3 w-3 animate-spin" />
          Sending...
        </span>
      )}
      {props.traceId && (
        <span data-testid="playground-trace-id">
          Last trace:{" "}
          <Link className="underline" href={`/traces/${props.traceId}`}>
            {props.traceId}
          </Link>
        </span>
      )}
      {props.error && (
        <span className="text-destructive" data-testid="playground-error">
          {props.error}
        </span>
      )}
    </div>
  );
}

function InputArea(props: {
  draft: string;
  setDraft: (v: string) => void;
  onKeyDown: (e: KeyboardEvent<HTMLTextAreaElement>) => void;
  onSend: () => void;
  disabled: boolean;
}): ReactElement {
  return (
    <div className="flex gap-2">
      <textarea
        data-testid="playground-input"
        value={props.draft}
        onChange={(e) => props.setDraft(e.target.value)}
        onKeyDown={props.onKeyDown}
        disabled={props.disabled}
        rows={3}
        placeholder="Type a message. Cmd/Ctrl+Enter to send."
        className="flex-1 rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
      />
      <Button
        type="button"
        onClick={props.onSend}
        disabled={props.disabled || props.draft.trim() === ""}
        data-testid="playground-send"
      >
        Send
      </Button>
    </div>
  );
}
