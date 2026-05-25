// ---------------------------------------------------------------------------
// Shared backend URL discovery used by both `proxy-helpers.ts` and the login
// route handler. Keeping the candidate list in one place avoids divergence.
// ---------------------------------------------------------------------------

const backendUrlCandidates: string[] = [
  process.env.LLMTRACE_PROXY_URL,
  process.env.LLMTRACE_BACKEND_URL,
  "http://llmtrace-proxy:8080",
  "http://llmtrace-proxy:8081",
  "http://127.0.0.1:8080",
  "http://127.0.0.1:8081",
  "http://localhost:8080",
  "http://localhost:8081",
].filter((value, index, arr): value is string => Boolean(value) && arr.indexOf(value) === index);

const RETRY_ON_404_PREFIXES: readonly string[] = [
  "/api/v1/config/live",
  "/config/live",
  "/swagger-ui",
  "/swagger-ui/",
  "/api-doc/openapi.json",
];

export interface BackendFetchResult {
  response: Response;
  backendUrl: string;
}

/**
 * Attempt the request against each known backend URL in order. The first URL
 * that produces a TCP-level connection wins; if a known-fallback path returns
 * 404 we try the next candidate (some deployments expose swagger only on the
 * admin port, for example).
 */
export async function fetchWithFallback(
  backendPath: string,
  init: RequestInit,
): Promise<BackendFetchResult> {
  let lastError: unknown;
  let lastResponse: Response | undefined;
  const normalizedPath = backendPath.split("?")[0] ?? backendPath;
  const shouldRetryOnNotFound = RETRY_ON_404_PREFIXES.some((p) =>
    normalizedPath.startsWith(p),
  );

  for (const backendUrl of backendUrlCandidates) {
    const url = new URL(backendPath, backendUrl);
    try {
      const response = await fetch(url.toString(), init);
      if (shouldRetryOnNotFound && response.status === 404) {
        lastResponse = response;
        continue;
      }
      return { response, backendUrl };
    } catch (error) {
      lastError = error;
    }
  }

  if (lastResponse) {
    return { response: lastResponse, backendUrl: "none" };
  }

  throw lastError ?? new Error("No backend URL candidates configured");
}
