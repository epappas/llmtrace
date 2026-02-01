//! Cost estimation engine for LLM API requests.
//!
//! Estimates per-request costs in USD based on the model, provider, and
//! token counts. Ships with a built-in pricing table for common commercial
//! models and supports:
//!
//! - **External pricing file** (`config/pricing.yaml`) loaded at startup
//!   and reloadable at runtime via [`CostEstimator::reload_pricing_file`]
//!   (e.g. on SIGHUP).
//! - **Custom pricing overrides** via [`CostEstimationConfig`] inline config.
//! - **Built-in fallback** when neither file nor custom config is available.
//!
//! Open/self-hosted models (Qwen, Llama, etc.) return `None` — there is no
//! standard pricing to apply.

use llmtrace_core::LLMProvider;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tracing::{info, warn};

// Re-export config types from core for public API convenience.
pub use llmtrace_core::{CostEstimationConfig, ModelPricingConfig};

// ---------------------------------------------------------------------------
// External pricing file schema
// ---------------------------------------------------------------------------

/// On-disk representation of a single model's pricing (YAML/JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilePricingEntry {
    /// Cost per 1 million input/prompt tokens in USD.
    pub input_per_million: f64,
    /// Cost per 1 million output/completion tokens in USD.
    pub output_per_million: f64,
}

/// The pricing file is a flat map: `model_name_prefix → FilePricingEntry`.
pub type PricingFile = HashMap<String, FilePricingEntry>;

/// Load a pricing YAML file from disk.
///
/// Returns `Ok(map)` on success or an error string on failure.
pub fn load_pricing_file(path: &str) -> Result<PricingFile, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read pricing file '{}': {}", path, e))?;
    serde_yaml::from_str::<PricingFile>(&contents)
        .map_err(|e| format!("Failed to parse pricing file '{}': {}", path, e))
}

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
/// Pricing sources are checked in this order (first match wins):
/// 1. Inline `custom_models` from [`CostEstimationConfig`]
/// 2. Entries loaded from the external pricing file
/// 3. Built-in hardcoded defaults
///
/// The pricing file can be reloaded at runtime via [`Self::reload_pricing_file`].
pub struct CostEstimator {
    /// Whether cost estimation is enabled.
    enabled: bool,
    /// Built-in pricing keyed by lowercase model prefix.
    builtin: HashMap<&'static str, Pricing>,
    /// Pricing loaded from an external YAML/JSON file, keyed by lowercase model name.
    file_pricing: HashMap<String, Pricing>,
    /// Custom pricing overrides from config, keyed by lowercase model name.
    custom: HashMap<String, Pricing>,
    /// Path to the pricing file (for reloads). `None` if no file was configured.
    pricing_file_path: Option<String>,
}

impl CostEstimator {
    /// Create a new estimator from the proxy cost-estimation config.
    ///
    /// If `config.pricing_file` is set, attempts to load it. On failure,
    /// logs a warning and falls back to built-in defaults.
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

        let (file_pricing, _) = Self::load_file_pricing(config.pricing_file.as_deref());

        Self {
            enabled: config.enabled,
            builtin: builtin_pricing(),
            file_pricing,
            custom,
            pricing_file_path: config.pricing_file.clone(),
        }
    }

    /// Attempt to load pricing from the configured file path.
    ///
    /// Returns `(map, resolved_path)`. On error the map is empty and a
    /// warning is logged.
    fn load_file_pricing(path: Option<&str>) -> (HashMap<String, Pricing>, Option<String>) {
        let Some(path) = path else {
            return (HashMap::new(), None);
        };

        if !Path::new(path).exists() {
            warn!(
                path = path,
                "Pricing file not found — using built-in defaults"
            );
            return (HashMap::new(), Some(path.to_string()));
        }

        match load_pricing_file(path) {
            Ok(entries) => {
                let count = entries.len();
                let map = entries
                    .into_iter()
                    .map(|(name, entry)| {
                        (
                            name.to_lowercase(),
                            Pricing {
                                input_per_million: entry.input_per_million,
                                output_per_million: entry.output_per_million,
                            },
                        )
                    })
                    .collect();
                info!(
                    path = path,
                    models = count,
                    "Loaded pricing from external file"
                );
                (map, Some(path.to_string()))
            }
            Err(e) => {
                warn!(
                    path = path,
                    error = %e,
                    "Failed to load pricing file — using built-in defaults"
                );
                (HashMap::new(), Some(path.to_string()))
            }
        }
    }

    /// Reload pricing from the configured file path.
    ///
    /// Call this on SIGHUP or config change to pick up updated pricing
    /// without a full proxy restart. Returns `true` if the file was
    /// successfully reloaded.
    pub fn reload_pricing_file(&mut self) -> bool {
        let path = match &self.pricing_file_path {
            Some(p) => p.clone(),
            None => return false,
        };

        match load_pricing_file(&path) {
            Ok(entries) => {
                let count = entries.len();
                self.file_pricing = entries
                    .into_iter()
                    .map(|(name, entry)| {
                        (
                            name.to_lowercase(),
                            Pricing {
                                input_per_million: entry.input_per_million,
                                output_per_million: entry.output_per_million,
                            },
                        )
                    })
                    .collect();
                info!(
                    path = path,
                    models = count,
                    "Reloaded pricing from external file"
                );
                true
            }
            Err(e) => {
                warn!(
                    path = path,
                    error = %e,
                    "Failed to reload pricing file — keeping existing pricing"
                );
                false
            }
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

    /// Look up pricing for a model name.
    ///
    /// Matching strategy (first match wins):
    /// 1. Exact match against custom entries (inline config, lowercase)
    /// 2. Exact match against file-loaded entries (lowercase)
    /// 3. Prefix match against file-loaded entries, longest prefix wins
    /// 4. Exact match against built-in entries (lowercase)
    /// 5. Prefix match against built-in entries, longest prefix wins
    fn lookup_pricing(&self, model: &str) -> Option<Pricing> {
        let lower = model.to_lowercase();

        // 1. Custom exact match (highest priority — inline config)
        if let Some(p) = self.custom.get(&lower) {
            return Some(*p);
        }

        // 2. File-loaded exact match
        if let Some(p) = self.file_pricing.get(&lower) {
            return Some(*p);
        }

        // 3. File-loaded prefix match (longest prefix wins)
        if let Some(p) = Self::prefix_match_owned(&self.file_pricing, &lower) {
            return Some(p);
        }

        // 4. Built-in exact match
        if let Some(p) = self.builtin.get(lower.as_str()) {
            return Some(*p);
        }

        // 5. Built-in prefix match (longest prefix wins)
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

    /// Prefix match against an owned `HashMap<String, Pricing>`.
    fn prefix_match_owned(map: &HashMap<String, Pricing>, lower: &str) -> Option<Pricing> {
        let mut best: Option<(&str, Pricing)> = None;
        for (prefix, &pricing) in map {
            if lower.starts_with(prefix.as_str()) {
                match best {
                    Some((bp, _)) if prefix.len() <= bp.len() => {}
                    _ => best = Some((prefix.as_str(), pricing)),
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
            pricing_file: None,
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
            pricing_file: None,
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
            pricing_file: None,
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
            pricing_file: None,
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

    // ======================================================================
    // External pricing file tests
    // ======================================================================

    #[test]
    fn test_load_pricing_file_valid_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pricing.yaml");
        std::fs::write(
            &path,
            r#"
my-custom-llm:
  input_per_million: 5.0
  output_per_million: 10.0
another-model:
  input_per_million: 1.0
  output_per_million: 2.0
"#,
        )
        .unwrap();

        let result = load_pricing_file(path.to_str().unwrap());
        assert!(result.is_ok());
        let map = result.unwrap();
        assert_eq!(map.len(), 2);
        assert!((map["my-custom-llm"].input_per_million - 5.0).abs() < 1e-6);
        assert!((map["another-model"].output_per_million - 2.0).abs() < 1e-6);
    }

    #[test]
    fn test_load_pricing_file_missing_file() {
        let result = load_pricing_file("/nonexistent/pricing.yaml");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to read"));
    }

    #[test]
    fn test_load_pricing_file_invalid_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.yaml");
        std::fs::write(&path, "this is not: [valid yaml: {").unwrap();

        let result = load_pricing_file(path.to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to parse"));
    }

    #[test]
    fn test_estimator_with_pricing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pricing.yaml");
        std::fs::write(
            &path,
            r#"
file-model:
  input_per_million: 7.0
  output_per_million: 14.0
"#,
        )
        .unwrap();

        let config = CostEstimationConfig {
            enabled: true,
            pricing_file: Some(path.to_str().unwrap().to_string()),
            custom_models: HashMap::new(),
        };
        let est = CostEstimator::new(&config);
        let cost = est
            .estimate_cost(
                &LLMProvider::OpenAI,
                "file-model",
                Some(1_000_000),
                Some(1_000_000),
            )
            .unwrap();
        // $7 + $14 = $21
        assert!((cost - 21.0).abs() < 1e-6);
    }

    #[test]
    fn test_file_pricing_prefix_match() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pricing.yaml");
        std::fs::write(
            &path,
            r#"
file-model:
  input_per_million: 7.0
  output_per_million: 14.0
"#,
        )
        .unwrap();

        let config = CostEstimationConfig {
            enabled: true,
            pricing_file: Some(path.to_str().unwrap().to_string()),
            custom_models: HashMap::new(),
        };
        let est = CostEstimator::new(&config);
        // "file-model-v2" should prefix-match "file-model"
        let cost = est
            .estimate_cost(
                &LLMProvider::OpenAI,
                "file-model-v2",
                Some(1_000_000),
                Some(1_000_000),
            )
            .unwrap();
        assert!((cost - 21.0).abs() < 1e-6);
    }

    #[test]
    fn test_custom_overrides_file_pricing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pricing.yaml");
        std::fs::write(
            &path,
            r#"
gpt-4o:
  input_per_million: 50.0
  output_per_million: 50.0
"#,
        )
        .unwrap();

        let config = CostEstimationConfig {
            enabled: true,
            pricing_file: Some(path.to_str().unwrap().to_string()),
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
        // Custom inline should win over file: $99 + $99 = $198
        assert!((cost - 198.0).abs() < 1e-6);
    }

    #[test]
    fn test_file_pricing_overrides_builtin() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pricing.yaml");
        std::fs::write(
            &path,
            r#"
gpt-4o:
  input_per_million: 50.0
  output_per_million: 50.0
"#,
        )
        .unwrap();

        let config = CostEstimationConfig {
            enabled: true,
            pricing_file: Some(path.to_str().unwrap().to_string()),
            custom_models: HashMap::new(),
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
        // File pricing should win over builtin: $50 + $50 = $100
        assert!((cost - 100.0).abs() < 1e-6);
    }

    #[test]
    fn test_fallback_to_builtin_when_file_missing() {
        let config = CostEstimationConfig {
            enabled: true,
            pricing_file: Some("/nonexistent/pricing.yaml".to_string()),
            custom_models: HashMap::new(),
        };
        let est = CostEstimator::new(&config);
        // Should still work with built-in pricing
        let cost = est
            .estimate_cost(
                &LLMProvider::OpenAI,
                "gpt-4o",
                Some(1_000_000),
                Some(1_000_000),
            )
            .unwrap();
        assert!((cost - 12.50).abs() < 1e-6);
    }

    #[test]
    fn test_fallback_to_builtin_when_file_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.yaml");
        std::fs::write(&path, "not valid yaml: [[[").unwrap();

        let config = CostEstimationConfig {
            enabled: true,
            pricing_file: Some(path.to_str().unwrap().to_string()),
            custom_models: HashMap::new(),
        };
        let est = CostEstimator::new(&config);
        // Should fall back to built-in pricing
        let cost = est
            .estimate_cost(
                &LLMProvider::OpenAI,
                "gpt-4o",
                Some(1_000_000),
                Some(1_000_000),
            )
            .unwrap();
        assert!((cost - 12.50).abs() < 1e-6);
    }

    #[test]
    fn test_reload_pricing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pricing.yaml");
        std::fs::write(
            &path,
            r#"
reload-model:
  input_per_million: 1.0
  output_per_million: 2.0
"#,
        )
        .unwrap();

        let config = CostEstimationConfig {
            enabled: true,
            pricing_file: Some(path.to_str().unwrap().to_string()),
            custom_models: HashMap::new(),
        };
        let mut est = CostEstimator::new(&config);
        let cost = est
            .estimate_cost(
                &LLMProvider::OpenAI,
                "reload-model",
                Some(1_000_000),
                Some(1_000_000),
            )
            .unwrap();
        assert!((cost - 3.0).abs() < 1e-6);

        // Update the file with new pricing
        std::fs::write(
            &path,
            r#"
reload-model:
  input_per_million: 10.0
  output_per_million: 20.0
"#,
        )
        .unwrap();

        assert!(est.reload_pricing_file());
        let cost = est
            .estimate_cost(
                &LLMProvider::OpenAI,
                "reload-model",
                Some(1_000_000),
                Some(1_000_000),
            )
            .unwrap();
        // $10 + $20 = $30
        assert!((cost - 30.0).abs() < 1e-6);
    }

    #[test]
    fn test_reload_returns_false_when_no_file_configured() {
        let mut est = default_estimator();
        assert!(!est.reload_pricing_file());
    }

    #[test]
    fn test_reload_keeps_existing_on_bad_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pricing.yaml");
        std::fs::write(
            &path,
            r#"
keep-model:
  input_per_million: 5.0
  output_per_million: 10.0
"#,
        )
        .unwrap();

        let config = CostEstimationConfig {
            enabled: true,
            pricing_file: Some(path.to_str().unwrap().to_string()),
            custom_models: HashMap::new(),
        };
        let mut est = CostEstimator::new(&config);
        let cost = est
            .estimate_cost(
                &LLMProvider::OpenAI,
                "keep-model",
                Some(1_000_000),
                Some(1_000_000),
            )
            .unwrap();
        assert!((cost - 15.0).abs() < 1e-6);

        // Corrupt the file
        std::fs::write(&path, "not valid yaml: [[[").unwrap();
        assert!(!est.reload_pricing_file());

        // Existing pricing should still work
        let cost = est
            .estimate_cost(
                &LLMProvider::OpenAI,
                "keep-model",
                Some(1_000_000),
                Some(1_000_000),
            )
            .unwrap();
        assert!((cost - 15.0).abs() < 1e-6);
    }

    #[test]
    fn test_load_real_config_pricing_yaml() {
        // Test that the actual config/pricing.yaml in the repo is valid
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/pricing.yaml");
        if std::path::Path::new(path).exists() {
            let result = load_pricing_file(path);
            assert!(result.is_ok(), "config/pricing.yaml should be valid YAML");
            let map = result.unwrap();
            assert!(!map.is_empty(), "config/pricing.yaml should not be empty");
            // Verify a known entry
            assert!(map.contains_key("gpt-4o"), "Should contain gpt-4o");
        }
    }
}
