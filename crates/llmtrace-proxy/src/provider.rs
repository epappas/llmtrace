//! LLM provider auto-detection and provider-specific response parsing.
//!
//! Detection sources (in priority order):
//! 1. Custom header `X-LLMTrace-Provider` for explicit override
//! 2. Upstream URL hostname (e.g., `api.openai.com` → OpenAI)
//! 3. Request URL path patterns (e.g., `/v1/messages` → Anthropic)
//!
//! Also provides provider-specific response parsing for usage metadata
//! and response text extraction.

use axum::http::HeaderMap;
use llmtrace_core::{AgentAction, AgentActionType, LLMProvider};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Provider detection
// ---------------------------------------------------------------------------

/// Detect the LLM provider from available request context.
///
/// Checks (in priority order):
/// 1. `X-LLMTrace-Provider` header — explicit override
/// 2. Upstream URL hostname — e.g., `api.openai.com`
/// 3. Request path pattern — e.g., `/v1/messages` → Anthropic
///
/// Falls back to [`LLMProvider::OpenAI`] if no signal matches.
pub fn detect_provider(headers: &HeaderMap, upstream_url: &str, request_path: &str) -> LLMProvider {
    // Priority 1: Explicit header override
    if let Some(provider) = detect_from_header(headers) {
        return provider;
    }

    // Priority 2: Upstream URL hostname
    if let Some(provider) = detect_from_hostname(upstream_url) {
        return provider;
    }

    // Priority 3: Request path patterns
    if let Some(provider) = detect_from_path(request_path) {
        return provider;
    }

    // Default fallback
    LLMProvider::OpenAI
}

/// Parse the `X-LLMTrace-Provider` header into an [`LLMProvider`].
fn detect_from_header(headers: &HeaderMap) -> Option<LLMProvider> {
    let value = headers.get("x-llmtrace-provider")?;
    let s = value.to_str().ok()?;
    parse_provider_name(s)
}

/// Detect provider from the upstream URL hostname.
fn detect_from_hostname(upstream_url: &str) -> Option<LLMProvider> {
    let lower = upstream_url.to_lowercase();

    if lower.contains("api.openai.com") {
        return Some(LLMProvider::OpenAI);
    }
    if lower.contains("api.anthropic.com") {
        return Some(LLMProvider::Anthropic);
    }
    if lower.contains("openai.azure.com") || lower.contains("cognitiveservices.azure.com") {
        return Some(LLMProvider::AzureOpenAI);
    }
    if lower.contains("bedrock-runtime") && lower.contains("amazonaws.com") {
        return Some(LLMProvider::Bedrock);
    }

    // Ollama typically runs on localhost:11434
    if lower.contains(":11434") {
        return Some(LLMProvider::Ollama);
    }

    None
}

/// Detect provider from the request URL path.
fn detect_from_path(path: &str) -> Option<LLMProvider> {
    // Anthropic
    if path.starts_with("/v1/messages") {
        return Some(LLMProvider::Anthropic);
    }

    // Ollama
    if path.starts_with("/api/generate")
        || path.starts_with("/api/chat")
        || path.starts_with("/api/tags")
        || path.starts_with("/api/embeddings")
    {
        return Some(LLMProvider::Ollama);
    }

    // OpenAI-compatible (covers vLLM, SGLang, TGI, and OpenAI itself)
    if path.starts_with("/v1/chat/completions")
        || path.starts_with("/v1/completions")
        || path.starts_with("/v1/embeddings")
    {
        return Some(LLMProvider::OpenAI);
    }

    None
}

/// Parse a provider name string (case-insensitive) into an [`LLMProvider`].
fn parse_provider_name(name: &str) -> Option<LLMProvider> {
    match name.to_lowercase().trim() {
        "openai" => Some(LLMProvider::OpenAI),
        "anthropic" => Some(LLMProvider::Anthropic),
        "vllm" => Some(LLMProvider::VLLm),
        "sglang" => Some(LLMProvider::SGLang),
        "tgi" => Some(LLMProvider::TGI),
        "ollama" => Some(LLMProvider::Ollama),
        "azure" | "azure_openai" | "azureopenai" => Some(LLMProvider::AzureOpenAI),
        "bedrock" => Some(LLMProvider::Bedrock),
        other if !other.is_empty() => Some(LLMProvider::Custom(other.to_string())),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Provider-specific response parsing
// ---------------------------------------------------------------------------

/// Token usage extracted from a provider response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderUsage {
    /// Number of prompt/input tokens.
    pub prompt_tokens: Option<u32>,
    /// Number of completion/output tokens.
    pub completion_tokens: Option<u32>,
    /// Total token count.
    pub total_tokens: Option<u32>,
}

/// Parsed response metadata from a non-streaming LLM response.
#[derive(Debug, Clone, Default)]
pub struct ParsedResponse {
    /// The main response text content.
    pub text: Option<String>,
    /// Token usage information.
    pub usage: ProviderUsage,
}

/// Extract response metadata from a non-streaming response body,
/// using the detected provider to select the appropriate format.
pub fn parse_response(provider: &LLMProvider, body: &[u8]) -> ParsedResponse {
    let Ok(parsed) = serde_json::from_slice::<Value>(body) else {
        return ParsedResponse::default();
    };

    match provider {
        LLMProvider::Anthropic => parse_anthropic_response(&parsed),
        LLMProvider::Ollama => parse_ollama_response(&parsed),
        LLMProvider::OpenAI
        | LLMProvider::VLLm
        | LLMProvider::SGLang
        | LLMProvider::TGI
        | LLMProvider::AzureOpenAI => parse_openai_response(&parsed),
        LLMProvider::Bedrock => parse_openai_response(&parsed),
        LLMProvider::Custom(_) => parse_openai_response(&parsed),
    }
}

/// Parse an OpenAI-compatible response.
///
/// ```json
/// {
///   "choices": [{"message": {"content": "..."}}],
///   "usage": {"prompt_tokens": N, "completion_tokens": N, "total_tokens": N}
/// }
/// ```
fn parse_openai_response(v: &Value) -> ParsedResponse {
    let text = v["choices"]
        .as_array()
        .and_then(|choices| choices.first())
        .and_then(|choice| choice["message"]["content"].as_str())
        .map(|s| s.to_string());

    let usage = &v["usage"];
    ParsedResponse {
        text,
        usage: ProviderUsage {
            prompt_tokens: usage["prompt_tokens"].as_u64().map(|n| n as u32),
            completion_tokens: usage["completion_tokens"].as_u64().map(|n| n as u32),
            total_tokens: usage["total_tokens"].as_u64().map(|n| n as u32),
        },
    }
}

/// Parse an Anthropic-style response.
///
/// ```json
/// {
///   "content": [{"type": "text", "text": "..."}],
///   "usage": {"input_tokens": N, "output_tokens": N}
/// }
/// ```
fn parse_anthropic_response(v: &Value) -> ParsedResponse {
    let text = v["content"]
        .as_array()
        .and_then(|blocks| {
            blocks.iter().find_map(|block| {
                if block["type"].as_str() == Some("text") {
                    block["text"].as_str().map(|s| s.to_string())
                } else {
                    None
                }
            })
        })
        // Fallback: if content is a simple array, try first element's text
        .or_else(|| {
            v["content"]
                .as_array()
                .and_then(|blocks| blocks.first())
                .and_then(|block| block["text"].as_str())
                .map(|s| s.to_string())
        });

    let usage = &v["usage"];
    let input_tokens = usage["input_tokens"].as_u64().map(|n| n as u32);
    let output_tokens = usage["output_tokens"].as_u64().map(|n| n as u32);
    let total = match (input_tokens, output_tokens) {
        (Some(i), Some(o)) => Some(i + o),
        _ => None,
    };

    ParsedResponse {
        text,
        usage: ProviderUsage {
            prompt_tokens: input_tokens,
            completion_tokens: output_tokens,
            total_tokens: total,
        },
    }
}

/// Parse an Ollama-style response.
///
/// Generate endpoint:
/// ```json
/// {"response": "...", "eval_count": N, "prompt_eval_count": N}
/// ```
///
/// Chat endpoint:
/// ```json
/// {"message": {"content": "..."}, "eval_count": N, "prompt_eval_count": N}
/// ```
fn parse_ollama_response(v: &Value) -> ParsedResponse {
    // Response text: try "message.content" (chat) then "response" (generate)
    let text = v["message"]["content"]
        .as_str()
        .or_else(|| v["response"].as_str())
        .map(|s| s.to_string());

    let eval_count = v["eval_count"].as_u64().map(|n| n as u32);
    let prompt_eval_count = v["prompt_eval_count"].as_u64().map(|n| n as u32);
    let total = match (prompt_eval_count, eval_count) {
        (Some(p), Some(e)) => Some(p + e),
        _ => None,
    };

    ParsedResponse {
        text,
        usage: ProviderUsage {
            prompt_tokens: prompt_eval_count,
            completion_tokens: eval_count,
            total_tokens: total,
        },
    }
}

// ---------------------------------------------------------------------------
// Tool call extraction from LLM responses
// ---------------------------------------------------------------------------

/// Extract agent actions (tool calls) from a non-streaming LLM response body.
///
/// Parses provider-specific tool call formats:
/// - **OpenAI**: `choices[].message.tool_calls[]` and legacy `function_call`
/// - **Anthropic**: `content[]` blocks with `type: "tool_use"`
///
/// Returns an empty vec if no tool calls are found or parsing fails.
pub fn extract_tool_calls(provider: &LLMProvider, body: &[u8]) -> Vec<AgentAction> {
    let Ok(parsed) = serde_json::from_slice::<Value>(body) else {
        return Vec::new();
    };

    match provider {
        LLMProvider::Anthropic => extract_anthropic_tool_calls(&parsed),
        _ => extract_openai_tool_calls(&parsed),
    }
}

/// Extract tool calls from an OpenAI-compatible response.
///
/// Handles both the modern `tool_calls` format and the legacy `function_call` format.
fn extract_openai_tool_calls(v: &Value) -> Vec<AgentAction> {
    let mut actions = Vec::new();

    if let Some(choices) = v["choices"].as_array() {
        for choice in choices {
            let message = &choice["message"];

            // Modern: tool_calls array
            if let Some(tool_calls) = message["tool_calls"].as_array() {
                for tc in tool_calls {
                    let name = tc["function"]["name"]
                        .as_str()
                        .unwrap_or("unknown")
                        .to_string();
                    let arguments = tc["function"]["arguments"]
                        .as_str()
                        .map(|s| truncate_string(s, llmtrace_core::AGENT_ACTION_RESULT_MAX_BYTES));
                    let mut action = AgentAction::new(AgentActionType::ToolCall, name);
                    action.arguments = arguments;
                    if let Some(id) = tc["id"].as_str() {
                        action
                            .metadata
                            .insert("tool_call_id".to_string(), id.to_string());
                    }
                    if let Some(tc_type) = tc["type"].as_str() {
                        action
                            .metadata
                            .insert("tool_type".to_string(), tc_type.to_string());
                    }
                    actions.push(action);
                }
            }

            // Legacy: function_call object
            if message["function_call"].is_object() {
                let fc = &message["function_call"];
                let name = fc["name"].as_str().unwrap_or("unknown").to_string();
                let arguments = fc["arguments"]
                    .as_str()
                    .map(|s| truncate_string(s, llmtrace_core::AGENT_ACTION_RESULT_MAX_BYTES));
                let mut action = AgentAction::new(AgentActionType::ToolCall, name);
                action.arguments = arguments;
                action
                    .metadata
                    .insert("legacy_function_call".to_string(), "true".to_string());
                actions.push(action);
            }
        }
    }

    actions
}

/// Extract tool calls from an Anthropic response.
///
/// Anthropic uses `content[]` blocks with `type: "tool_use"`.
fn extract_anthropic_tool_calls(v: &Value) -> Vec<AgentAction> {
    let mut actions = Vec::new();

    if let Some(content) = v["content"].as_array() {
        for block in content {
            if block["type"].as_str() == Some("tool_use") {
                let name = block["name"].as_str().unwrap_or("unknown").to_string();
                let arguments = if block["input"].is_object() {
                    Some(truncate_string(
                        &block["input"].to_string(),
                        llmtrace_core::AGENT_ACTION_RESULT_MAX_BYTES,
                    ))
                } else {
                    None
                };
                let mut action = AgentAction::new(AgentActionType::ToolCall, name);
                action.arguments = arguments;
                if let Some(id) = block["id"].as_str() {
                    action
                        .metadata
                        .insert("tool_use_id".to_string(), id.to_string());
                }
                actions.push(action);
            }
        }
    }

    actions
}

/// Truncate a string to the given byte limit, respecting UTF-8 boundaries.
fn truncate_string(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        s.to_string()
    } else {
        // Find a valid UTF-8 boundary
        let mut end = max_bytes;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        s[..end].to_string()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Header detection ---------------------------------------------------

    #[test]
    fn test_detect_from_header_openai() {
        let mut headers = HeaderMap::new();
        headers.insert("x-llmtrace-provider", "openai".parse().unwrap());
        assert_eq!(detect_from_header(&headers), Some(LLMProvider::OpenAI));
    }

    #[test]
    fn test_detect_from_header_anthropic() {
        let mut headers = HeaderMap::new();
        headers.insert("x-llmtrace-provider", "Anthropic".parse().unwrap());
        assert_eq!(detect_from_header(&headers), Some(LLMProvider::Anthropic));
    }

    #[test]
    fn test_detect_from_header_ollama() {
        let mut headers = HeaderMap::new();
        headers.insert("x-llmtrace-provider", "ollama".parse().unwrap());
        assert_eq!(detect_from_header(&headers), Some(LLMProvider::Ollama));
    }

    #[test]
    fn test_detect_from_header_vllm() {
        let mut headers = HeaderMap::new();
        headers.insert("x-llmtrace-provider", "vllm".parse().unwrap());
        assert_eq!(detect_from_header(&headers), Some(LLMProvider::VLLm));
    }

    #[test]
    fn test_detect_from_header_sglang() {
        let mut headers = HeaderMap::new();
        headers.insert("x-llmtrace-provider", "sglang".parse().unwrap());
        assert_eq!(detect_from_header(&headers), Some(LLMProvider::SGLang));
    }

    #[test]
    fn test_detect_from_header_tgi() {
        let mut headers = HeaderMap::new();
        headers.insert("x-llmtrace-provider", "tgi".parse().unwrap());
        assert_eq!(detect_from_header(&headers), Some(LLMProvider::TGI));
    }

    #[test]
    fn test_detect_from_header_azure() {
        let mut headers = HeaderMap::new();
        headers.insert("x-llmtrace-provider", "azure".parse().unwrap());
        assert_eq!(detect_from_header(&headers), Some(LLMProvider::AzureOpenAI));
    }

    #[test]
    fn test_detect_from_header_azure_openai() {
        let mut headers = HeaderMap::new();
        headers.insert("x-llmtrace-provider", "azure_openai".parse().unwrap());
        assert_eq!(detect_from_header(&headers), Some(LLMProvider::AzureOpenAI));
    }

    #[test]
    fn test_detect_from_header_bedrock() {
        let mut headers = HeaderMap::new();
        headers.insert("x-llmtrace-provider", "bedrock".parse().unwrap());
        assert_eq!(detect_from_header(&headers), Some(LLMProvider::Bedrock));
    }

    #[test]
    fn test_detect_from_header_custom() {
        let mut headers = HeaderMap::new();
        headers.insert("x-llmtrace-provider", "my-provider".parse().unwrap());
        assert_eq!(
            detect_from_header(&headers),
            Some(LLMProvider::Custom("my-provider".to_string()))
        );
    }

    #[test]
    fn test_detect_from_header_missing() {
        let headers = HeaderMap::new();
        assert_eq!(detect_from_header(&headers), None);
    }

    #[test]
    fn test_detect_from_header_empty() {
        let mut headers = HeaderMap::new();
        headers.insert("x-llmtrace-provider", "".parse().unwrap());
        assert_eq!(detect_from_header(&headers), None);
    }

    // ---- Hostname detection -------------------------------------------------

    #[test]
    fn test_detect_from_hostname_openai() {
        assert_eq!(
            detect_from_hostname("https://api.openai.com"),
            Some(LLMProvider::OpenAI)
        );
    }

    #[test]
    fn test_detect_from_hostname_anthropic() {
        assert_eq!(
            detect_from_hostname("https://api.anthropic.com"),
            Some(LLMProvider::Anthropic)
        );
    }

    #[test]
    fn test_detect_from_hostname_azure() {
        assert_eq!(
            detect_from_hostname("https://myinstance.openai.azure.com"),
            Some(LLMProvider::AzureOpenAI)
        );
    }

    #[test]
    fn test_detect_from_hostname_azure_cognitive() {
        assert_eq!(
            detect_from_hostname("https://myinstance.cognitiveservices.azure.com"),
            Some(LLMProvider::AzureOpenAI)
        );
    }

    #[test]
    fn test_detect_from_hostname_bedrock() {
        assert_eq!(
            detect_from_hostname("https://bedrock-runtime.us-east-1.amazonaws.com"),
            Some(LLMProvider::Bedrock)
        );
    }

    #[test]
    fn test_detect_from_hostname_ollama_default_port() {
        assert_eq!(
            detect_from_hostname("http://localhost:11434"),
            Some(LLMProvider::Ollama)
        );
    }

    #[test]
    fn test_detect_from_hostname_unknown() {
        assert_eq!(detect_from_hostname("http://localhost:8000"), None);
    }

    // ---- Path detection -----------------------------------------------------

    #[test]
    fn test_detect_from_path_anthropic_messages() {
        assert_eq!(
            detect_from_path("/v1/messages"),
            Some(LLMProvider::Anthropic)
        );
    }

    #[test]
    fn test_detect_from_path_ollama_generate() {
        assert_eq!(detect_from_path("/api/generate"), Some(LLMProvider::Ollama));
    }

    #[test]
    fn test_detect_from_path_ollama_chat() {
        assert_eq!(detect_from_path("/api/chat"), Some(LLMProvider::Ollama));
    }

    #[test]
    fn test_detect_from_path_openai_chat_completions() {
        assert_eq!(
            detect_from_path("/v1/chat/completions"),
            Some(LLMProvider::OpenAI)
        );
    }

    #[test]
    fn test_detect_from_path_openai_completions() {
        assert_eq!(
            detect_from_path("/v1/completions"),
            Some(LLMProvider::OpenAI)
        );
    }

    #[test]
    fn test_detect_from_path_unknown() {
        assert_eq!(detect_from_path("/some/unknown/path"), None);
    }

    // ---- Full detection priority --------------------------------------------

    #[test]
    fn test_detect_provider_header_overrides_hostname() {
        let mut headers = HeaderMap::new();
        headers.insert("x-llmtrace-provider", "anthropic".parse().unwrap());
        // Hostname says OpenAI, but header overrides
        let provider = detect_provider(&headers, "https://api.openai.com", "/v1/chat/completions");
        assert_eq!(provider, LLMProvider::Anthropic);
    }

    #[test]
    fn test_detect_provider_hostname_overrides_path() {
        let headers = HeaderMap::new();
        // Hostname says Anthropic, path says OpenAI-compatible
        let provider = detect_provider(
            &headers,
            "https://api.anthropic.com",
            "/v1/chat/completions",
        );
        assert_eq!(provider, LLMProvider::Anthropic);
    }

    #[test]
    fn test_detect_provider_path_fallback() {
        let headers = HeaderMap::new();
        // Unknown hostname, but path gives a hint
        let provider = detect_provider(&headers, "http://my-custom-server:8000", "/v1/messages");
        assert_eq!(provider, LLMProvider::Anthropic);
    }

    #[test]
    fn test_detect_provider_default_fallback() {
        let headers = HeaderMap::new();
        let provider = detect_provider(&headers, "http://unknown:9999", "/unknown/path");
        assert_eq!(provider, LLMProvider::OpenAI);
    }

    // ---- OpenAI response parsing --------------------------------------------

    #[test]
    fn test_parse_openai_response() {
        let body = serde_json::json!({
            "id": "chatcmpl-abc",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Hello! How can I help you?"
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 8,
                "total_tokens": 18
            }
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let parsed = parse_response(&LLMProvider::OpenAI, &bytes);

        assert_eq!(parsed.text, Some("Hello! How can I help you?".to_string()));
        assert_eq!(parsed.usage.prompt_tokens, Some(10));
        assert_eq!(parsed.usage.completion_tokens, Some(8));
        assert_eq!(parsed.usage.total_tokens, Some(18));
    }

    #[test]
    fn test_parse_openai_response_no_usage() {
        let body = serde_json::json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "Hi"
                }
            }]
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let parsed = parse_response(&LLMProvider::OpenAI, &bytes);

        assert_eq!(parsed.text, Some("Hi".to_string()));
        assert_eq!(parsed.usage.prompt_tokens, None);
    }

    #[test]
    fn test_parse_openai_response_empty_choices() {
        let body = serde_json::json!({
            "choices": [],
            "usage": {"prompt_tokens": 5, "completion_tokens": 0, "total_tokens": 5}
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let parsed = parse_response(&LLMProvider::OpenAI, &bytes);

        assert_eq!(parsed.text, None);
        assert_eq!(parsed.usage.prompt_tokens, Some(5));
    }

    // ---- Anthropic response parsing -----------------------------------------

    #[test]
    fn test_parse_anthropic_response() {
        let body = serde_json::json!({
            "id": "msg_abc",
            "type": "message",
            "role": "assistant",
            "content": [{
                "type": "text",
                "text": "Hello from Claude!"
            }],
            "usage": {
                "input_tokens": 15,
                "output_tokens": 5
            }
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let parsed = parse_response(&LLMProvider::Anthropic, &bytes);

        assert_eq!(parsed.text, Some("Hello from Claude!".to_string()));
        assert_eq!(parsed.usage.prompt_tokens, Some(15));
        assert_eq!(parsed.usage.completion_tokens, Some(5));
        assert_eq!(parsed.usage.total_tokens, Some(20));
    }

    #[test]
    fn test_parse_anthropic_response_multiple_blocks() {
        let body = serde_json::json!({
            "content": [
                {"type": "text", "text": "First block"},
                {"type": "text", "text": "Second block"}
            ],
            "usage": {
                "input_tokens": 10,
                "output_tokens": 20
            }
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let parsed = parse_response(&LLMProvider::Anthropic, &bytes);

        // Should extract the first text block
        assert_eq!(parsed.text, Some("First block".to_string()));
        assert_eq!(parsed.usage.total_tokens, Some(30));
    }

    #[test]
    fn test_parse_anthropic_response_no_usage() {
        let body = serde_json::json!({
            "content": [{"type": "text", "text": "Hi"}]
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let parsed = parse_response(&LLMProvider::Anthropic, &bytes);

        assert_eq!(parsed.text, Some("Hi".to_string()));
        assert_eq!(parsed.usage.prompt_tokens, None);
        assert_eq!(parsed.usage.completion_tokens, None);
        assert_eq!(parsed.usage.total_tokens, None);
    }

    // ---- Ollama response parsing --------------------------------------------

    #[test]
    fn test_parse_ollama_generate_response() {
        let body = serde_json::json!({
            "model": "llama3",
            "response": "Here is the answer.",
            "done": true,
            "eval_count": 12,
            "prompt_eval_count": 8
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let parsed = parse_response(&LLMProvider::Ollama, &bytes);

        assert_eq!(parsed.text, Some("Here is the answer.".to_string()));
        assert_eq!(parsed.usage.prompt_tokens, Some(8));
        assert_eq!(parsed.usage.completion_tokens, Some(12));
        assert_eq!(parsed.usage.total_tokens, Some(20));
    }

    #[test]
    fn test_parse_ollama_chat_response() {
        let body = serde_json::json!({
            "model": "llama3",
            "message": {
                "role": "assistant",
                "content": "Chat answer"
            },
            "done": true,
            "eval_count": 6,
            "prompt_eval_count": 4
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let parsed = parse_response(&LLMProvider::Ollama, &bytes);

        assert_eq!(parsed.text, Some("Chat answer".to_string()));
        assert_eq!(parsed.usage.prompt_tokens, Some(4));
        assert_eq!(parsed.usage.completion_tokens, Some(6));
        assert_eq!(parsed.usage.total_tokens, Some(10));
    }

    #[test]
    fn test_parse_ollama_response_no_eval_counts() {
        let body = serde_json::json!({
            "response": "Partial response",
            "done": false
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let parsed = parse_response(&LLMProvider::Ollama, &bytes);

        assert_eq!(parsed.text, Some("Partial response".to_string()));
        assert_eq!(parsed.usage.prompt_tokens, None);
        assert_eq!(parsed.usage.completion_tokens, None);
        assert_eq!(parsed.usage.total_tokens, None);
    }

    // ---- Edge cases ---------------------------------------------------------

    #[test]
    fn test_parse_response_invalid_json() {
        let parsed = parse_response(&LLMProvider::OpenAI, b"not json");
        assert_eq!(parsed.text, None);
        assert_eq!(parsed.usage, ProviderUsage::default());
    }

    #[test]
    fn test_parse_response_empty_body() {
        let parsed = parse_response(&LLMProvider::Anthropic, b"");
        assert_eq!(parsed.text, None);
        assert_eq!(parsed.usage, ProviderUsage::default());
    }

    #[test]
    fn test_parse_response_vllm_uses_openai_format() {
        let body = serde_json::json!({
            "choices": [{"message": {"content": "vLLM says hi"}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let parsed = parse_response(&LLMProvider::VLLm, &bytes);

        assert_eq!(parsed.text, Some("vLLM says hi".to_string()));
        assert_eq!(parsed.usage.prompt_tokens, Some(5));
    }

    #[test]
    fn test_parse_response_custom_uses_openai_format() {
        let body = serde_json::json!({
            "choices": [{"message": {"content": "Custom provider"}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3}
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let parsed = parse_response(&LLMProvider::Custom("mine".to_string()), &bytes);

        assert_eq!(parsed.text, Some("Custom provider".to_string()));
        assert_eq!(parsed.usage.total_tokens, Some(3));
    }

    // ---- parse_provider_name ------------------------------------------------

    #[test]
    fn test_parse_provider_name_case_insensitive() {
        assert_eq!(parse_provider_name("OPENAI"), Some(LLMProvider::OpenAI));
        assert_eq!(
            parse_provider_name("Anthropic"),
            Some(LLMProvider::Anthropic)
        );
        assert_eq!(parse_provider_name("OLLAMA"), Some(LLMProvider::Ollama));
    }

    #[test]
    fn test_parse_provider_name_with_whitespace() {
        assert_eq!(parse_provider_name("  openai  "), Some(LLMProvider::OpenAI));
    }

    #[test]
    fn test_parse_provider_name_azure_variants() {
        assert_eq!(parse_provider_name("azure"), Some(LLMProvider::AzureOpenAI));
        assert_eq!(
            parse_provider_name("azure_openai"),
            Some(LLMProvider::AzureOpenAI)
        );
        assert_eq!(
            parse_provider_name("azureopenai"),
            Some(LLMProvider::AzureOpenAI)
        );
    }

    // ---- Tool call extraction: OpenAI ---------------------------------------

    #[test]
    fn test_extract_openai_tool_calls() {
        let body = serde_json::json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [
                        {
                            "id": "call_abc123",
                            "type": "function",
                            "function": {
                                "name": "get_weather",
                                "arguments": "{\"location\": \"London\"}"
                            }
                        },
                        {
                            "id": "call_def456",
                            "type": "function",
                            "function": {
                                "name": "get_time",
                                "arguments": "{\"timezone\": \"UTC\"}"
                            }
                        }
                    ]
                }
            }]
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let actions = extract_tool_calls(&LLMProvider::OpenAI, &bytes);

        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0].name, "get_weather");
        assert_eq!(actions[0].action_type, AgentActionType::ToolCall);
        assert_eq!(
            actions[0].arguments,
            Some("{\"location\": \"London\"}".to_string())
        );
        assert_eq!(
            actions[0].metadata.get("tool_call_id"),
            Some(&"call_abc123".to_string())
        );
        assert_eq!(actions[1].name, "get_time");
    }

    #[test]
    fn test_extract_openai_legacy_function_call() {
        let body = serde_json::json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": null,
                    "function_call": {
                        "name": "calculate",
                        "arguments": "{\"expr\": \"2+2\"}"
                    }
                }
            }]
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let actions = extract_tool_calls(&LLMProvider::OpenAI, &bytes);

        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].name, "calculate");
        assert_eq!(
            actions[0].metadata.get("legacy_function_call"),
            Some(&"true".to_string())
        );
    }

    #[test]
    fn test_extract_openai_no_tool_calls() {
        let body = serde_json::json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "Hello!"
                }
            }]
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let actions = extract_tool_calls(&LLMProvider::OpenAI, &bytes);
        assert!(actions.is_empty());
    }

    // ---- Tool call extraction: Anthropic ------------------------------------

    #[test]
    fn test_extract_anthropic_tool_use() {
        let body = serde_json::json!({
            "id": "msg_abc",
            "type": "message",
            "role": "assistant",
            "content": [
                {"type": "text", "text": "Let me check the weather."},
                {
                    "type": "tool_use",
                    "id": "toolu_xyz",
                    "name": "get_weather",
                    "input": {"location": "Paris", "unit": "celsius"}
                }
            ]
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let actions = extract_tool_calls(&LLMProvider::Anthropic, &bytes);

        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].name, "get_weather");
        assert_eq!(actions[0].action_type, AgentActionType::ToolCall);
        assert!(actions[0].arguments.as_ref().unwrap().contains("Paris"));
        assert_eq!(
            actions[0].metadata.get("tool_use_id"),
            Some(&"toolu_xyz".to_string())
        );
    }

    #[test]
    fn test_extract_anthropic_no_tool_use() {
        let body = serde_json::json!({
            "content": [{"type": "text", "text": "Just text here."}]
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let actions = extract_tool_calls(&LLMProvider::Anthropic, &bytes);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_extract_anthropic_multiple_tool_uses() {
        let body = serde_json::json!({
            "content": [
                {"type": "tool_use", "id": "t1", "name": "search", "input": {"q": "rust"}},
                {"type": "text", "text": "interim"},
                {"type": "tool_use", "id": "t2", "name": "read_file", "input": {"path": "/tmp"}}
            ]
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let actions = extract_tool_calls(&LLMProvider::Anthropic, &bytes);
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0].name, "search");
        assert_eq!(actions[1].name, "read_file");
    }

    // ---- Tool call extraction: edge cases -----------------------------------

    #[test]
    fn test_extract_tool_calls_invalid_json() {
        let actions = extract_tool_calls(&LLMProvider::OpenAI, b"not json");
        assert!(actions.is_empty());
    }

    #[test]
    fn test_extract_tool_calls_empty_body() {
        let actions = extract_tool_calls(&LLMProvider::OpenAI, b"");
        assert!(actions.is_empty());
    }

    #[test]
    fn test_truncate_string_within_limit() {
        assert_eq!(truncate_string("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_string_exceeds_limit() {
        let result = truncate_string("hello world", 5);
        assert_eq!(result, "hello");
    }

    #[test]
    fn test_truncate_string_respects_utf8() {
        // "héllo" — 'é' is 2 bytes in UTF-8, so total is 6 bytes
        let s = "héllo";
        let result = truncate_string(s, 3);
        // Truncating at byte 3 would be in the middle of 'l',
        // so should include "hé" (3 bytes)
        assert_eq!(result, "hé");
    }
}
