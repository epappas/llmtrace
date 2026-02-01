//! Standalone cost estimation for WASM.
//!
//! This is a self-contained reimplementation of the cost estimator from
//! `llmtrace-proxy` that avoids pulling in protoc/gRPC dependencies.
//! It ships with the same built-in pricing table and supports custom
//! model pricing.

use std::collections::HashMap;

/// Pricing entry: cost per 1 million input/output tokens.
#[derive(Debug, Clone, Copy)]
struct Pricing {
    input_per_million: f64,
    output_per_million: f64,
}

/// Cost estimator with built-in and custom model pricing.
pub struct CostEstimator {
    /// Built-in pricing keyed by lowercase model prefix.
    builtin: HashMap<&'static str, Pricing>,
    /// Custom pricing overrides keyed by lowercase model name.
    custom: HashMap<String, Pricing>,
}

impl CostEstimator {
    /// Create a new estimator with built-in pricing for common models.
    pub fn new() -> Self {
        Self {
            builtin: builtin_pricing(),
            custom: HashMap::new(),
        }
    }

    /// Add custom pricing for a model (per 1 million tokens).
    pub fn add_custom(&mut self, model: &str, input_per_million: f64, output_per_million: f64) {
        self.custom.insert(
            model.to_lowercase(),
            Pricing {
                input_per_million,
                output_per_million,
            },
        );
    }

    /// Estimate cost in USD for a request.
    ///
    /// Returns `None` if the model is not recognised.
    pub fn estimate(&self, model: &str, prompt_tokens: u32, completion_tokens: u32) -> Option<f64> {
        let pricing = self.lookup(model)?;
        let input_cost = prompt_tokens as f64 * pricing.input_per_million / 1_000_000.0;
        let output_cost = completion_tokens as f64 * pricing.output_per_million / 1_000_000.0;
        Some(input_cost + output_cost)
    }

    /// List all known model names (built-in + custom).
    pub fn known_models(&self) -> Vec<String> {
        let mut models: Vec<String> = self.builtin.keys().map(|k| (*k).to_string()).collect();
        for key in self.custom.keys() {
            if !models.contains(key) {
                models.push(key.clone());
            }
        }
        models.sort();
        models
    }

    /// Look up pricing: custom exact → built-in exact → built-in prefix (longest wins).
    fn lookup(&self, model: &str) -> Option<Pricing> {
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

/// Built-in pricing table for well-known commercial models (mid-2025).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpt4o_pricing() {
        let est = CostEstimator::new();
        let cost = est.estimate("gpt-4o", 1_000_000, 1_000_000).unwrap();
        assert!((cost - 12.50).abs() < 1e-6);
    }

    #[test]
    fn test_gpt4o_mini_pricing() {
        let est = CostEstimator::new();
        let cost = est.estimate("gpt-4o-mini", 1_000_000, 1_000_000).unwrap();
        assert!((cost - 0.75).abs() < 1e-6);
    }

    #[test]
    fn test_claude_opus_pricing() {
        let est = CostEstimator::new();
        let cost = est
            .estimate("claude-3-opus-20240229", 1_000_000, 1_000_000)
            .unwrap();
        assert!((cost - 90.0).abs() < 1e-6);
    }

    #[test]
    fn test_prefix_match() {
        let est = CostEstimator::new();
        let cost = est
            .estimate("gpt-4o-2024-08-06", 1_000_000, 1_000_000)
            .unwrap();
        assert!((cost - 12.50).abs() < 1e-6);
    }

    #[test]
    fn test_prefix_prefers_longest() {
        let est = CostEstimator::new();
        let cost = est
            .estimate("gpt-4o-mini-2024-07-18", 1_000_000, 1_000_000)
            .unwrap();
        // Should match gpt-4o-mini, not gpt-4o
        assert!((cost - 0.75).abs() < 1e-6);
    }

    #[test]
    fn test_unknown_returns_none() {
        let est = CostEstimator::new();
        assert!(est.estimate("unknown-model", 100, 50).is_none());
    }

    #[test]
    fn test_custom_pricing() {
        let mut est = CostEstimator::new();
        est.add_custom("my-model", 5.0, 10.0);
        let cost = est.estimate("my-model", 1_000_000, 1_000_000).unwrap();
        assert!((cost - 15.0).abs() < 1e-6);
    }

    #[test]
    fn test_custom_overrides_builtin() {
        let mut est = CostEstimator::new();
        est.add_custom("gpt-4o", 99.0, 99.0);
        let cost = est.estimate("gpt-4o", 1_000_000, 1_000_000).unwrap();
        assert!((cost - 198.0).abs() < 1e-6);
    }

    #[test]
    fn test_case_insensitive() {
        let est = CostEstimator::new();
        let cost = est.estimate("GPT-4O", 1_000_000, 1_000_000).unwrap();
        assert!((cost - 12.50).abs() < 1e-6);
    }

    #[test]
    fn test_zero_tokens() {
        let est = CostEstimator::new();
        let cost = est.estimate("gpt-4o", 0, 0).unwrap();
        assert!((cost - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_known_models() {
        let est = CostEstimator::new();
        let models = est.known_models();
        assert!(models.contains(&"gpt-4o".to_string()));
        assert!(models.contains(&"claude-3-5-sonnet".to_string()));
    }

    #[test]
    fn test_known_models_includes_custom() {
        let mut est = CostEstimator::new();
        est.add_custom("my-custom-llm", 1.0, 2.0);
        let models = est.known_models();
        assert!(models.contains(&"my-custom-llm".to_string()));
    }

    #[test]
    fn test_realistic_small_request() {
        let est = CostEstimator::new();
        // 500 prompt + 200 completion with gpt-4o-mini
        let cost = est.estimate("gpt-4o-mini", 500, 200).unwrap();
        let expected = (500.0 * 0.15 + 200.0 * 0.60) / 1_000_000.0;
        assert!((cost - expected).abs() < 1e-10);
    }
}
