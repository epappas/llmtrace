//! Cost estimation engine for LLM API requests.
//!
//! Estimates per-request costs in USD based on the model, provider, and
//! token counts. Ships with a built-in pricing table for common commercial
//! models and supports custom pricing overrides via [`CostEstimationConfig`].
//!
//! Open/self-hosted models (Qwen, Llama, etc.) return `None` — there is no
//! standard pricing to apply.

use llmtrace_core::LLMProvider;
use std::collections::HashMap;

// Re-export config types from core for public API convenience.
pub use llmtrace_core::{CostEstimationConfig, ModelPricingConfig};

// ---------------------------------------------------------------------------
// Built-in pricing table (per 1 million tokens)
// ---------------------------------------------------------------------------

/// Pricing entry for a model: cost per 1 million input and output tokens.
#[derive(Debug, Clone, Copy)]
struct Pricing {
    input_per_million: f64,
    output_per_million: f64,
}

/// Build the default pricing table for well-known commercial models.
///
/// Prices are sourced from provider pricing pages (as of mid-2025).
/// Keys are lowercase model name prefixes — lookup tries both exact match
/// and prefix match so that `gpt-4o-2024-08-06` matches the `gpt-4o` entry.
fn builtin_pricing() -> HashMap<&'static str, Pricing> {
    let mut m = HashMap::new();

    // OpenAI
    m.insert(
        "gpt-4o-mini",
        Pricing {
            input_per_million: 0.15,
            output_per_million: 0.60,
        },
    );
    m.insert(
        "gpt-4o",
        Pricing {
            input_per_million: 2.50,
            output_per_million: 10.0,
        },
    );
    m.insert(
        "gpt-4",
        Pricing {
            input_per_million: 30.0,
            output_per_million: 60.0,
        },
    );
    m.insert(
        "gpt-3.5-turbo",
        Pricing {
            input_per_million: 0.50,
            output_per_million: 1.50,
        },
    );

    // Anthropic
    m.insert(
        "claude-3-5-sonnet",
        Pricing {
            input_per_million: 3.0,
            output_per_million: 15.0,
        },
    );
    m.insert(
        "claude-3.5-sonnet",
        Pricing {
            input_per_million: 3.0,
            output_per_million: 15.0,
        },
    );
    m.insert(
        "claude-3-5-haiku",
        Pricing {
            input_per_million: 0.80,
            output_per_million: 4.0,
        },
    );
    m.insert(
        "claude-3.5-haiku",
        Pricing {
            input_per_million: 0.80,
            output_per_million: 4.0,
        },
    );
    m.insert(
        "claude-3-opus",
        Pricing {
            input_per_million: 15.0,
            output_per_million: 75.0,
        },
    );

    m
}

// ---------------------------------------------------------------------------
// Cost estimator
// ---------------------------------------------------------------------------

/// Estimates per-request cost in USD from model name and token counts.
///
/// Holds both built-in pricing and any custom overrides from configuration.
/// Custom entries take precedence over built-in pricing for the same model.
pub struct CostEstimator {
    /// Whether cost estimation is enabled.
    enabled: bool,
    /// Built-in pricing keyed by lowercase model prefix.
    builtin: HashMap<&'static str, Pricing>,
    /// Custom pricing overrides from config, keyed by lowercase model name.
    custom: HashMap<String, Pricing>,
}

impl CostEstimator {
    /// Create a new estimator from the proxy cost-estimation config.
    pub fn new(config: &CostEstimationConfig) -> Self {
        let custom = config
            .custom_models
            .iter()
            .map(|(name, mc)| {
                (
                    name.to_lowercase(),
                    Pricing {
                        input_per_million: mc.input_per_million,
                        output_per_million: mc.output_per_million,
                    },
                )
            })
            .collect();

        Self {
            enabled: config.enabled,
            builtin: builtin_pricing(),
            custom,
        }
    }

    /// Estimate cost for a request.
    ///
    /// Returns `None` when:
    /// - Cost estimation is disabled
    /// - The provider is self-hosted (VLLm, SGLang, TGI, Ollama)
    /// - The model is not recognised and no custom pricing exists
    /// - Token counts are both missing
    #[must_use]
    pub fn estimate_cost(
        &self,
        provider: &LLMProvider,
        model: &str,
        prompt_tokens: Option<u32>,
        completion_tokens: Option<u32>,
    ) -> Option<f64> {
        if !self.enabled {
            return None;
        }

        // Self-hosted / open-source providers have no standard pricing
        if is_self_hosted(provider) {
            return None;
        }

        let pricing = self.lookup_pricing(model)?;

        let input_cost =
            prompt_tokens.unwrap_or(0) as f64 * pricing.input_per_million / 1_000_000.0;
        let output_cost =
            completion_tokens.unwrap_or(0) as f64 * pricing.output_per_million / 1_000_000.0;

        Some(input_cost + output_cost)
    }

    /// Look up pricing for a model name. Custom entries take precedence.
    ///
    /// Matching strategy:
    /// 1. Exact match against custom entries (lowercase)
    /// 2. Exact match against built-in entries (lowercase)
    /// 3. Prefix match against built-in entries, longest prefix wins
    fn lookup_pricing(&self, model: &str) -> Option<Pricing> {
        let lower = model.to_lowercase();

        // 1. Custom exact match
        if let Some(p) = self.custom.get(&lower) {
            return Some(*p);
        }

        // 2. Built-in exact match
        if let Some(p) = self.builtin.get(lower.as_str()) {
            return Some(*p);
        }

        // 3. Built-in prefix match (longest prefix wins)
        let mut best: Option<(&str, Pricing)> = None;
        for (&prefix, &pricing) in &self.builtin {
            if lower.starts_with(prefix) {
                match best {
                    Some((bp, _)) if prefix.len() <= bp.len() => {}
                    _ => best = Some((prefix, pricing)),
                }
            }
        }
        best.map(|(_, p)| p)
    }
}

/// Returns `true` for providers that typically run self-hosted models with
/// no standard per-token pricing.
fn is_self_hosted(provider: &LLMProvider) -> bool {
    matches!(
        provider,
        LLMProvider::VLLm | LLMProvider::SGLang | LLMProvider::TGI | LLMProvider::Ollama
    )
}

// ---------------------------------------------------------------------------
// Convenience constructor for use from ProxyConfig
// ---------------------------------------------------------------------------

/// Build a [`CostEstimator`] directly from a [`CostEstimationConfig`] reference.
impl From<&CostEstimationConfig> for CostEstimator {
    fn from(config: &CostEstimationConfig) -> Self {
        Self::new(config)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: estimator with default (enabled, no custom models) config.
    fn default_estimator() -> CostEstimator {
        CostEstimator::new(&CostEstimationConfig::default())
    }

    // ---- Known models -------------------------------------------------------

    #[test]
    fn test_gpt4_pricing() {
        let est = default_estimator();
        let cost = est
            .estimate_cost(
                &LLMProvider::OpenAI,
                "gpt-4",
                Some(1_000_000),
                Some(1_000_000),
            )
            .unwrap();
        // $30 input + $60 output = $90
        assert!((cost - 90.0).abs() < 1e-6);
    }

    #[test]
    fn test_gpt4o_pricing() {
        let est = default_estimator();
        let cost = est
            .estimate_cost(
                &LLMProvider::OpenAI,
                "gpt-4o",
                Some(1_000_000),
                Some(1_000_000),
            )
            .unwrap();
        // $2.50 + $10 = $12.50
        assert!((cost - 12.50).abs() < 1e-6);
    }

    #[test]
    fn test_gpt4o_mini_pricing() {
        let est = default_estimator();
        let cost = est
            .estimate_cost(
                &LLMProvider::OpenAI,
                "gpt-4o-mini",
                Some(1_000_000),
                Some(1_000_000),
            )
            .unwrap();
        // $0.15 + $0.60 = $0.75
        assert!((cost - 0.75).abs() < 1e-6);
    }

    #[test]
    fn test_gpt35_turbo_pricing() {
        let est = default_estimator();
        let cost = est
            .estimate_cost(
                &LLMProvider::OpenAI,
                "gpt-3.5-turbo",
                Some(1_000_000),
                Some(1_000_000),
            )
            .unwrap();
        // $0.50 + $1.50 = $2.00
        assert!((cost - 2.0).abs() < 1e-6);
    }

    #[test]
    fn test_claude_35_sonnet_pricing() {
        let est = default_estimator();
        let cost = est
            .estimate_cost(
                &LLMProvider::Anthropic,
                "claude-3-5-sonnet-20241022",
                Some(1_000_000),
                Some(1_000_000),
            )
            .unwrap();
        // $3 + $15 = $18
        assert!((cost - 18.0).abs() < 1e-6);
    }

    #[test]
    fn test_claude_35_sonnet_dot_notation() {
        let est = default_estimator();
        let cost = est
            .estimate_cost(
                &LLMProvider::Anthropic,
                "claude-3.5-sonnet-20241022",
                Some(1_000_000),
                Some(1_000_000),
            )
            .unwrap();
        assert!((cost - 18.0).abs() < 1e-6);
    }

    #[test]
    fn test_claude_35_haiku_pricing() {
        let est = default_estimator();
        let cost = est
            .estimate_cost(
                &LLMProvider::Anthropic,
                "claude-3-5-haiku-20241022",
                Some(1_000_000),
                Some(1_000_000),
            )
            .unwrap();
        // $0.80 + $4 = $4.80
        assert!((cost - 4.80).abs() < 1e-6);
    }

    #[test]
    fn test_claude_3_opus_pricing() {
        let est = default_estimator();
        let cost = est
            .estimate_cost(
                &LLMProvider::Anthropic,
                "claude-3-opus-20240229",
                Some(1_000_000),
                Some(1_000_000),
            )
            .unwrap();
        // $15 + $75 = $90
        assert!((cost - 90.0).abs() < 1e-6);
    }

    // ---- Prefix matching ----------------------------------------------------

    #[test]
    fn test_prefix_match_gpt4o_dated() {
        let est = default_estimator();
        let cost = est
            .estimate_cost(
                &LLMProvider::OpenAI,
                "gpt-4o-2024-08-06",
                Some(1000),
                Some(500),
            )
            .unwrap();
        // gpt-4o pricing: (1000 * 2.50 + 500 * 10) / 1_000_000
        let expected = (1000.0 * 2.50 + 500.0 * 10.0) / 1_000_000.0;
        assert!((cost - expected).abs() < 1e-10);
    }

    #[test]
    fn test_prefix_match_prefers_longest() {
        // "gpt-4o-mini-2024-07-18" should match "gpt-4o-mini" (len 11) not "gpt-4o" (len 6)
        let est = default_estimator();
        let cost = est
            .estimate_cost(
                &LLMProvider::OpenAI,
                "gpt-4o-mini-2024-07-18",
                Some(1_000_000),
                Some(1_000_000),
            )
            .unwrap();
        // gpt-4o-mini: $0.15 + $0.60 = $0.75
        assert!((cost - 0.75).abs() < 1e-6);
    }

    // ---- Unknown models -----------------------------------------------------

    #[test]
    fn test_unknown_model_returns_none() {
        let est = default_estimator();
        assert!(est
            .estimate_cost(
                &LLMProvider::OpenAI,
                "some-unknown-model-v42",
                Some(100),
                Some(50)
            )
            .is_none());
    }

    // ---- Self-hosted providers return None -----------------------------------

    #[test]
    fn test_vllm_returns_none() {
        let est = default_estimator();
        assert!(est
            .estimate_cost(&LLMProvider::VLLm, "gpt-4o", Some(100), Some(50))
            .is_none());
    }

    #[test]
    fn test_sglang_returns_none() {
        let est = default_estimator();
        assert!(est
            .estimate_cost(&LLMProvider::SGLang, "gpt-4o", Some(100), Some(50))
            .is_none());
    }

    #[test]
    fn test_tgi_returns_none() {
        let est = default_estimator();
        assert!(est
            .estimate_cost(&LLMProvider::TGI, "gpt-4o", Some(100), Some(50))
            .is_none());
    }

    #[test]
    fn test_ollama_returns_none() {
        let est = default_estimator();
        assert!(est
            .estimate_cost(&LLMProvider::Ollama, "llama3", Some(100), Some(50))
            .is_none());
    }

    // ---- Zero tokens --------------------------------------------------------

    #[test]
    fn test_zero_tokens_returns_zero_cost() {
        let est = default_estimator();
        let cost = est
            .estimate_cost(&LLMProvider::OpenAI, "gpt-4o", Some(0), Some(0))
            .unwrap();
        assert!((cost - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_none_tokens_returns_zero_cost() {
        let est = default_estimator();
        let cost = est
            .estimate_cost(&LLMProvider::OpenAI, "gpt-4o", None, None)
            .unwrap();
        assert!((cost - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_partial_tokens_only_input() {
        let est = default_estimator();
        let cost = est
            .estimate_cost(&LLMProvider::OpenAI, "gpt-4o", Some(1_000_000), None)
            .unwrap();
        // Only input cost: $2.50
        assert!((cost - 2.50).abs() < 1e-6);
    }

    #[test]
    fn test_partial_tokens_only_output() {
        let est = default_estimator();
        let cost = est
            .estimate_cost(&LLMProvider::OpenAI, "gpt-4o", None, Some(1_000_000))
            .unwrap();
        // Only output cost: $10
        assert!((cost - 10.0).abs() < 1e-6);
    }

    // ---- Custom pricing -----------------------------------------------------

    #[test]
    fn test_custom_model_pricing() {
        let config = CostEstimationConfig {
            enabled: true,
            custom_models: {
                let mut m = HashMap::new();
                m.insert(
                    "my-custom-model".to_string(),
                    ModelPricingConfig {
                        input_per_million: 1.0,
                        output_per_million: 2.0,
                    },
                );
                m
            },
        };
        let est = CostEstimator::new(&config);
        let cost = est
            .estimate_cost(
                &LLMProvider::OpenAI,
                "my-custom-model",
                Some(1_000_000),
                Some(1_000_000),
            )
            .unwrap();
        // $1 + $2 = $3
        assert!((cost - 3.0).abs() < 1e-6);
    }

    #[test]
    fn test_custom_pricing_overrides_builtin() {
        let config = CostEstimationConfig {
            enabled: true,
            custom_models: {
                let mut m = HashMap::new();
                m.insert(
                    "gpt-4o".to_string(),
                    ModelPricingConfig {
                        input_per_million: 99.0,
                        output_per_million: 99.0,
                    },
                );
                m
            },
        };
        let est = CostEstimator::new(&config);
        let cost = est
            .estimate_cost(
                &LLMProvider::OpenAI,
                "gpt-4o",
                Some(1_000_000),
                Some(1_000_000),
            )
            .unwrap();
        // Custom: $99 + $99 = $198
        assert!((cost - 198.0).abs() < 1e-6);
    }

    #[test]
    fn test_custom_pricing_case_insensitive() {
        let config = CostEstimationConfig {
            enabled: true,
            custom_models: {
                let mut m = HashMap::new();
                m.insert(
                    "My-Model".to_string(),
                    ModelPricingConfig {
                        input_per_million: 5.0,
                        output_per_million: 10.0,
                    },
                );
                m
            },
        };
        let est = CostEstimator::new(&config);
        let cost = est
            .estimate_cost(
                &LLMProvider::OpenAI,
                "my-model",
                Some(1_000_000),
                Some(1_000_000),
            )
            .unwrap();
        assert!((cost - 15.0).abs() < 1e-6);
    }

    // ---- Disabled estimation ------------------------------------------------

    #[test]
    fn test_disabled_returns_none() {
        let config = CostEstimationConfig {
            enabled: false,
            custom_models: HashMap::new(),
        };
        let est = CostEstimator::new(&config);
        assert!(est
            .estimate_cost(&LLMProvider::OpenAI, "gpt-4o", Some(100), Some(50))
            .is_none());
    }

    // ---- Commercial non-self-hosted providers work --------------------------

    #[test]
    fn test_azure_openai_uses_pricing() {
        let est = default_estimator();
        let cost = est.estimate_cost(
            &LLMProvider::AzureOpenAI,
            "gpt-4o",
            Some(1_000_000),
            Some(1_000_000),
        );
        assert!(cost.is_some());
        assert!((cost.unwrap() - 12.50).abs() < 1e-6);
    }

    #[test]
    fn test_bedrock_with_claude_uses_pricing() {
        let est = default_estimator();
        let cost = est.estimate_cost(
            &LLMProvider::Bedrock,
            "claude-3-opus-20240229",
            Some(1_000_000),
            Some(1_000_000),
        );
        assert!(cost.is_some());
        assert!((cost.unwrap() - 90.0).abs() < 1e-6);
    }

    // ---- Realistic small request --------------------------------------------

    #[test]
    fn test_realistic_small_request() {
        let est = default_estimator();
        // 500 prompt tokens, 200 completion tokens with gpt-4o-mini
        let cost = est
            .estimate_cost(&LLMProvider::OpenAI, "gpt-4o-mini", Some(500), Some(200))
            .unwrap();
        // (500 * 0.15 + 200 * 0.60) / 1_000_000 = (75 + 120) / 1_000_000 = 0.000195
        let expected = (500.0 * 0.15 + 200.0 * 0.60) / 1_000_000.0;
        assert!((cost - expected).abs() < 1e-10);
    }
}
