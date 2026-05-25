import type { ReactElement } from "react";
import { ProxyConnectionBanner } from "@/components/proxy-connection-banner";
import TenantsClient from "./_client";

// The connection banner reads `process.env.LLMTRACE_PROXY_URL` at request
// time (the env var is injected by deployments/basilica/lifecycle.py when
// the dashboard container starts). Force dynamic rendering so the value is
// resolved at runtime, not baked in at `next build`.
export const dynamic = "force-dynamic";

/**
 * Server component wrapper for /tenants.
 *
 * Renders the proxy "Connection" banner at the top so a tenant operator can
 * discover the public proxy URL their applications must POST to, then
 * delegates the interactive tenant table to the client component.
 */
export default function TenantsPage(): ReactElement {
  return (
    <div className="space-y-6">
      <ProxyConnectionBanner />
      <TenantsClient />
    </div>
  );
}
