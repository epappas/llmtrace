import type { ReactElement } from "react";
import { ProxyConnectionBannerClient } from "./proxy-connection-banner-client";

/**
 * Server component: reads LLMTRACE_PROXY_URL from the server-side env
 * (injected by deployments/basilica/lifecycle.py during provisioning) and
 * delegates rendering to a small client component for interactivity.
 *
 * Server components can be safely composed inside client components in the
 * Next.js App Router, but the env var must be read here so we can keep the
 * parent page free of build-time env coupling.
 */
export function ProxyConnectionBanner(): ReactElement {
  const proxyUrl: string = (process.env.LLMTRACE_PROXY_URL ?? "").trim();
  return <ProxyConnectionBannerClient proxyUrl={proxyUrl} />;
}
