import type { ReactElement } from "react";
import PlaygroundClient from "./_client";

// Force dynamic rendering: the playground POSTs through `/api/proxy/...`
// at request time, so there is no static output worth caching.
export const dynamic = "force-dynamic";

/**
 * Server component wrapper for /playground (issue #284).
 *
 * The interactive chat panel lives in the `_client` module; this server
 * shell renders the lead copy and embeds it. No data is fetched here —
 * the client component drives the whole conversation in memory.
 */
export default function PlaygroundPage(): ReactElement {
  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <h1 className="text-3xl font-bold">Playground</h1>
        <p className="text-sm text-muted-foreground">
          Send chat-style requests through your proxy URL. Useful for quick
          smoke tests and verifying upstream provider auth. Traces and findings
          show up in the Traces / Security / Audit pages as usual.
        </p>
      </div>
      <PlaygroundClient />
    </div>
  );
}
