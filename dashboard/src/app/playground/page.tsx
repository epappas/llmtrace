import type { ReactElement } from "react";
import PlaygroundClient from "./_client";

// Force dynamic rendering: the playground POSTs through `/api/proxy/...`
// at request time, so there is no static output worth caching.
export const dynamic = "force-dynamic";

/**
 * Server component wrapper for /playground.
 *
 * The interactive chat experience (header, transcript, composer, settings
 * drawer, per-message LLMTrace metadata) lives entirely in `_client`.
 * This shell exists only to mark the route dynamic and embed the client.
 * Issue #287 moved the heading + lead copy into the chat header so the
 * conversation surface can occupy the full viewport.
 */
export default function PlaygroundPage(): ReactElement {
  return <PlaygroundClient />;
}
