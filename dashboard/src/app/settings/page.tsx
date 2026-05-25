import SettingsClient from "./settings-client";

export const dynamic = "force-dynamic";

export default function SettingsPage() {
  const proxyUrl = process.env.LLMTRACE_PROXY_URL ?? "";
  return <SettingsClient proxyUrl={proxyUrl} />;
}
