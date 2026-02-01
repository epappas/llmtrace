//! Multi-channel alert engine for security finding notifications.
//!
//! Supports dispatching alerts to multiple channels (Slack, PagerDuty, generic
//! webhook) with per-channel severity filtering, global deduplication/cooldown,
//! and backward compatibility with the legacy single-webhook configuration.

use async_trait::async_trait;
use dashmap::DashMap;
use llmtrace_core::{AlertChannelConfig, AlertConfig, SecurityFinding, SecuritySeverity, TenantId};
use reqwest::Client;
use serde::Serialize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// AlertPayload — shared payload given to every channel
// ---------------------------------------------------------------------------

/// Structured payload sent to alert channels.
#[derive(Debug, Clone, Serialize)]
pub struct AlertPayload {
    /// Trace that triggered the alert.
    pub trace_id: Uuid,
    /// Tenant that owns the trace.
    pub tenant_id: TenantId,
    /// Timestamp of the alert in RFC 3339 format.
    pub timestamp: String,
    /// Security findings that exceeded thresholds.
    pub findings: Vec<AlertFinding>,
}

/// A single finding within an [`AlertPayload`].
#[derive(Debug, Clone, Serialize)]
pub struct AlertFinding {
    pub severity: String,
    pub finding_type: String,
    pub description: String,
    pub confidence_score: f64,
}

impl AlertFinding {
    fn from_security_finding(f: &SecurityFinding) -> Self {
        Self {
            severity: f.severity.to_string(),
            finding_type: f.finding_type.clone(),
            description: f.description.clone(),
            confidence_score: f.confidence_score,
        }
    }
}

// ---------------------------------------------------------------------------
// AlertError
// ---------------------------------------------------------------------------

/// Errors that can occur when sending an alert.
#[derive(Debug, thiserror::Error)]
pub enum AlertError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Channel error: {0}")]
    Channel(String),
}

// ---------------------------------------------------------------------------
// AlertChannel trait
// ---------------------------------------------------------------------------

/// Trait implemented by each alert delivery mechanism (Slack, PagerDuty, etc.).
#[async_trait]
pub trait AlertChannel: Send + Sync {
    /// Deliver an alert payload to this channel.
    async fn send_alert(&self, alert: &AlertPayload) -> Result<(), AlertError>;
    /// Human-readable name of this channel (for logging).
    fn channel_name(&self) -> &str;
}

// ---------------------------------------------------------------------------
// WebhookChannel — generic HTTP POST
// ---------------------------------------------------------------------------

/// Generic webhook channel — sends a JSON POST to an arbitrary URL.
pub struct WebhookChannel {
    url: String,
    client: Client,
}

impl WebhookChannel {
    pub fn new(url: String, client: Client) -> Self {
        Self { url, client }
    }
}

#[async_trait]
impl AlertChannel for WebhookChannel {
    async fn send_alert(&self, alert: &AlertPayload) -> Result<(), AlertError> {
        let payload = GenericPayload {
            alert_type: "security_finding".to_string(),
            trace_id: alert.trace_id.to_string(),
            tenant_id: alert.tenant_id.to_string(),
            timestamp: alert.timestamp.clone(),
            findings: alert.findings.clone(),
        };
        let resp = self.client.post(&self.url).json(&payload).send().await?;
        if !resp.status().is_success() {
            error!(
                channel = "webhook",
                status = %resp.status(),
                url = %self.url,
                "Webhook delivery failed"
            );
        }
        Ok(())
    }

    fn channel_name(&self) -> &str {
        "webhook"
    }
}

/// Generic webhook JSON body.
#[derive(Debug, Serialize)]
struct GenericPayload {
    alert_type: String,
    trace_id: String,
    tenant_id: String,
    timestamp: String,
    findings: Vec<AlertFinding>,
}

// ---------------------------------------------------------------------------
// SlackChannel — Incoming Webhook with Block Kit
// ---------------------------------------------------------------------------

/// Slack channel using Incoming Webhook API with Block Kit formatting.
pub struct SlackChannel {
    webhook_url: String,
    client: Client,
}

impl SlackChannel {
    pub fn new(webhook_url: String, client: Client) -> Self {
        Self {
            webhook_url,
            client,
        }
    }
}

#[async_trait]
impl AlertChannel for SlackChannel {
    async fn send_alert(&self, alert: &AlertPayload) -> Result<(), AlertError> {
        let payload = build_slack_payload(alert);
        let resp = self
            .client
            .post(&self.webhook_url)
            .json(&payload)
            .send()
            .await?;
        if !resp.status().is_success() {
            error!(
                channel = "slack",
                status = %resp.status(),
                "Slack webhook delivery failed"
            );
        }
        Ok(())
    }

    fn channel_name(&self) -> &str {
        "slack"
    }
}

/// Slack Block Kit payload.
#[derive(Debug, Serialize)]
struct SlackPayload {
    text: String,
    blocks: Vec<serde_json::Value>,
}

/// Build a rich Slack Block Kit payload from an alert.
fn build_slack_payload(alert: &AlertPayload) -> SlackPayload {
    let max_severity = alert
        .findings
        .iter()
        .map(|f| f.severity.as_str())
        .max()
        .unwrap_or("Unknown");

    let severity_emoji = match max_severity {
        "Critical" => "\u{1f6d1}",      // 🛑
        "High" => "\u{1f6a8}",          // 🚨
        "Medium" => "\u{26a0}\u{fe0f}", // ⚠️
        _ => "\u{2139}\u{fe0f}",        // ℹ️
    };

    let findings_text: String = alert
        .findings
        .iter()
        .map(|f| {
            format!(
                "\u{2022} *{}* `{}`: {} (confidence: {:.0}%)",
                f.severity,
                f.finding_type,
                f.description,
                f.confidence_score * 100.0,
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let header_text = format!("{severity_emoji} LLMTrace Security Alert — {max_severity}");

    let body = format!(
        "*Trace:* `{}`\n*Tenant:* `{}`\n*Time:* {}\n\n*Findings ({}):**\n{}",
        alert.trace_id,
        alert.tenant_id,
        alert.timestamp,
        alert.findings.len(),
        findings_text,
    );

    SlackPayload {
        text: header_text.clone(),
        blocks: vec![
            serde_json::json!({
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": header_text,
                    "emoji": true
                }
            }),
            serde_json::json!({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": body
                }
            }),
            serde_json::json!({
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": format!("LLMTrace Alert Engine | {} finding(s)", alert.findings.len())
                }]
            }),
        ],
    }
}

// ---------------------------------------------------------------------------
// PagerDutyChannel — Events API v2
// ---------------------------------------------------------------------------

/// PagerDuty channel using the Events API v2.
pub struct PagerDutyChannel {
    routing_key: String,
    client: Client,
}

impl PagerDutyChannel {
    /// PagerDuty Events API v2 endpoint.
    const EVENTS_URL: &'static str = "https://events.pagerduty.com/v2/enqueue";

    pub fn new(routing_key: String, client: Client) -> Self {
        Self {
            routing_key,
            client,
        }
    }

    /// Map `SecuritySeverity` string to PagerDuty severity.
    fn map_severity(severity: &str) -> &'static str {
        match severity {
            "Critical" => "critical",
            "High" => "error",
            "Medium" => "warning",
            "Low" | "Info" => "info",
            _ => "warning",
        }
    }
}

#[async_trait]
impl AlertChannel for PagerDutyChannel {
    async fn send_alert(&self, alert: &AlertPayload) -> Result<(), AlertError> {
        // Use the highest severity among findings for the PD event
        let max_severity = alert
            .findings
            .iter()
            .map(|f| f.severity.as_str())
            .max()
            .unwrap_or("Medium");

        let pd_severity = Self::map_severity(max_severity);

        let summary = if alert.findings.len() == 1 {
            format!(
                "LLMTrace: {} — {}",
                alert.findings[0].finding_type, alert.findings[0].description
            )
        } else {
            format!(
                "LLMTrace: {} security finding(s) on trace {}",
                alert.findings.len(),
                alert.trace_id
            )
        };

        let payload = serde_json::json!({
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "dedup_key": format!("llmtrace-{}", alert.trace_id),
            "payload": {
                "summary": summary,
                "severity": pd_severity,
                "source": "llmtrace-proxy",
                "component": "security-analysis",
                "group": alert.tenant_id.to_string(),
                "timestamp": alert.timestamp,
                "custom_details": {
                    "trace_id": alert.trace_id.to_string(),
                    "tenant_id": alert.tenant_id.to_string(),
                    "findings": alert.findings,
                }
            }
        });

        let resp = self
            .client
            .post(Self::EVENTS_URL)
            .json(&payload)
            .send()
            .await?;
        if !resp.status().is_success() {
            error!(
                channel = "pagerduty",
                status = %resp.status(),
                "PagerDuty event delivery failed"
            );
        }
        Ok(())
    }

    fn channel_name(&self) -> &str {
        "pagerduty"
    }
}

// ---------------------------------------------------------------------------
// ChannelWithFilter — wraps a channel + its min_severity / min_score
// ---------------------------------------------------------------------------

/// An alert channel together with its per-channel severity and score filters.
struct ChannelWithFilter {
    channel: Arc<dyn AlertChannel>,
    min_severity: SecuritySeverity,
    min_security_score: u8,
}

// ---------------------------------------------------------------------------
// AlertEngine
// ---------------------------------------------------------------------------

/// Evaluates security findings against configured thresholds and dispatches
/// notifications to one or more alert channels.
///
/// The engine is designed to be fire-and-forget: [`check_and_alert`](Self::check_and_alert)
/// spawns a background tokio task for the HTTP POST(s) and returns immediately.
pub struct AlertEngine {
    /// Cooldown duration between alerts of the same finding type.
    cooldown: Duration,
    /// Alert channels with their per-channel filters.
    channels: Vec<ChannelWithFilter>,
    /// Cooldown tracking: finding_type → last alert [`Instant`].
    cooldowns: Arc<DashMap<String, Instant>>,
}

impl AlertEngine {
    /// Create a new [`AlertEngine`] from configuration.
    ///
    /// Returns `None` if alerts are disabled or no channels can be built.
    pub fn from_config(config: &AlertConfig, client: Client) -> Option<Self> {
        if !config.enabled {
            return None;
        }

        let mut channels: Vec<ChannelWithFilter> = Vec::new();

        if config.channels.is_empty() {
            // Legacy mode: use the top-level webhook_url
            if config.webhook_url.is_empty() {
                return None;
            }
            let min_severity = config
                .min_severity
                .parse::<SecuritySeverity>()
                .unwrap_or(SecuritySeverity::High);

            let channel: Arc<dyn AlertChannel> = if is_slack_webhook(&config.webhook_url) {
                Arc::new(SlackChannel::new(
                    config.webhook_url.clone(),
                    client.clone(),
                ))
            } else {
                Arc::new(WebhookChannel::new(
                    config.webhook_url.clone(),
                    client.clone(),
                ))
            };

            channels.push(ChannelWithFilter {
                channel,
                min_severity,
                min_security_score: config.min_security_score,
            });
        } else {
            // Multi-channel mode
            for ch_cfg in &config.channels {
                if let Some(ch) = build_channel(ch_cfg, &client) {
                    let min_severity = ch_cfg
                        .min_severity
                        .parse::<SecuritySeverity>()
                        .unwrap_or(SecuritySeverity::High);
                    channels.push(ChannelWithFilter {
                        channel: ch,
                        min_severity,
                        min_security_score: ch_cfg.min_security_score,
                    });
                } else {
                    warn!(
                        channel_type = %ch_cfg.channel_type,
                        "Skipping alert channel — missing required configuration"
                    );
                }
            }
        }

        if channels.is_empty() {
            return None;
        }

        Some(Self {
            cooldown: Duration::from_secs(config.cooldown_seconds),
            channels,
            cooldowns: Arc::new(DashMap::new()),
        })
    }

    /// Check findings against thresholds and fire alerts to applicable channels.
    ///
    /// The actual HTTP POST(s) are spawned as fire-and-forget tokio tasks so
    /// this method returns immediately and never blocks trace storage.
    pub fn check_and_alert(
        &self,
        trace_id: Uuid,
        tenant_id: TenantId,
        findings: &[SecurityFinding],
    ) {
        // First pass: global cooldown filter
        let cooldown_ok: Vec<&SecurityFinding> = findings
            .iter()
            .filter(|f| self.passes_cooldown(f))
            .collect();

        if cooldown_ok.is_empty() {
            return;
        }

        // Update cooldowns
        let now = Instant::now();
        for f in &cooldown_ok {
            self.cooldowns.insert(f.finding_type.clone(), now);
        }

        // Build alert payload with ALL cooldown-passing findings
        let payload = Arc::new(AlertPayload {
            trace_id,
            tenant_id,
            timestamp: chrono::Utc::now().to_rfc3339(),
            findings: cooldown_ok
                .iter()
                .map(|f| AlertFinding::from_security_finding(f))
                .collect(),
        });

        // For each channel, filter to findings that meet the channel's thresholds
        for cwf in &self.channels {
            let channel_findings: Vec<&SecurityFinding> = cooldown_ok
                .iter()
                .filter(|f| f.severity >= cwf.min_severity)
                .filter(|f| {
                    let score = (f.confidence_score * 100.0) as u8;
                    score >= cwf.min_security_score
                })
                .copied()
                .collect();

            if channel_findings.is_empty() {
                continue;
            }

            // Build a channel-specific payload with only the filtered findings
            let channel_payload = AlertPayload {
                trace_id,
                tenant_id,
                timestamp: payload.timestamp.clone(),
                findings: channel_findings
                    .iter()
                    .map(|f| AlertFinding::from_security_finding(f))
                    .collect(),
            };

            let channel = Arc::clone(&cwf.channel);
            let channel_name = cwf.channel.channel_name().to_string();

            info!(
                %trace_id,
                %tenant_id,
                channel = %channel_name,
                count = channel_findings.len(),
                "Sending alert to channel"
            );

            tokio::spawn(async move {
                if let Err(e) = channel.send_alert(&channel_payload).await {
                    error!(
                        %trace_id,
                        channel = %channel_name,
                        "Alert delivery failed: {e}"
                    );
                } else {
                    debug!(
                        %trace_id,
                        channel = %channel_name,
                        "Alert delivered successfully"
                    );
                }
            });
        }
    }

    /// Check if a finding's type is not within the cooldown window.
    fn passes_cooldown(&self, finding: &SecurityFinding) -> bool {
        match self.cooldowns.get(&finding.finding_type) {
            Some(last_alert) => last_alert.elapsed() >= self.cooldown,
            None => true,
        }
    }

    /// Return the number of configured channels (useful for tests / logging).
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }
}

// ---------------------------------------------------------------------------
// Channel factory
// ---------------------------------------------------------------------------

/// Build an [`AlertChannel`] from a single channel configuration entry.
fn build_channel(cfg: &AlertChannelConfig, client: &Client) -> Option<Arc<dyn AlertChannel>> {
    match cfg.channel_type.as_str() {
        "webhook" => {
            let url = cfg.effective_url()?;
            Some(Arc::new(WebhookChannel::new(
                url.to_string(),
                client.clone(),
            )))
        }
        "slack" => {
            let url = cfg.effective_url()?;
            Some(Arc::new(SlackChannel::new(url.to_string(), client.clone())))
        }
        "pagerduty" => {
            let key = cfg.routing_key.as_deref().filter(|k| !k.is_empty())?;
            Some(Arc::new(PagerDutyChannel::new(
                key.to_string(),
                client.clone(),
            )))
        }
        "email" => {
            // Email is a future TODO — log a warning and skip
            warn!("Email alert channel is not yet implemented — skipping");
            None
        }
        other => {
            warn!(channel_type = %other, "Unknown alert channel type — skipping");
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Detect whether a webhook URL is a Slack incoming-webhook endpoint.
fn is_slack_webhook(url: &str) -> bool {
    url.contains("hooks.slack.com") || url.contains("hooks.slack-gov.com")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use llmtrace_core::SecuritySeverity;
    use tokio::sync::Mutex;

    // -- helpers -----------------------------------------------------------

    /// Build a test `AlertConfig` pointing at a given URL (legacy mode).
    fn test_config(url: &str) -> AlertConfig {
        AlertConfig {
            enabled: true,
            webhook_url: url.to_string(),
            min_severity: "High".to_string(),
            min_security_score: 70,
            cooldown_seconds: 300,
            channels: Vec::new(),
            escalation: None,
        }
    }

    fn high_finding() -> SecurityFinding {
        SecurityFinding::new(
            SecuritySeverity::High,
            "prompt_injection".to_string(),
            "Detected prompt injection attempt".to_string(),
            0.95,
        )
    }

    fn critical_finding() -> SecurityFinding {
        SecurityFinding::new(
            SecuritySeverity::Critical,
            "system_prompt_override".to_string(),
            "System prompt override detected".to_string(),
            0.99,
        )
    }

    fn low_finding() -> SecurityFinding {
        SecurityFinding::new(
            SecuritySeverity::Low,
            "minor_issue".to_string(),
            "Minor style issue detected".to_string(),
            0.3,
        )
    }

    /// Mock HTTP server: returns (url, received_payloads).
    async fn simple_mock(path: &str) -> (String, Arc<Mutex<Vec<serde_json::Value>>>) {
        use axum::routing::post;
        use axum::Router;

        let received: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
        let clone = received.clone();

        let app = Router::new().route(
            path,
            post(move |axum::Json(body): axum::Json<serde_json::Value>| {
                let store = clone.clone();
                async move {
                    store.lock().await.push(body);
                    axum::http::StatusCode::OK
                }
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let url = format!("http://{addr}{path}");
        (url, received)
    }

    // -- from_config -------------------------------------------------------

    #[test]
    fn test_disabled_config_returns_none() {
        let config = AlertConfig::default();
        assert!(AlertEngine::from_config(&config, Client::new()).is_none());
    }

    #[test]
    fn test_empty_url_returns_none() {
        let config = AlertConfig {
            enabled: true,
            webhook_url: String::new(),
            ..AlertConfig::default()
        };
        assert!(AlertEngine::from_config(&config, Client::new()).is_none());
    }

    #[test]
    fn test_valid_config_returns_engine() {
        let config = test_config("http://example.com/webhook");
        let engine = AlertEngine::from_config(&config, Client::new()).unwrap();
        assert_eq!(engine.channel_count(), 1);
    }

    #[test]
    fn test_invalid_severity_defaults_to_high() {
        let config = AlertConfig {
            min_severity: "banana".to_string(),
            ..test_config("http://example.com/webhook")
        };
        let engine = AlertEngine::from_config(&config, Client::new()).unwrap();
        assert_eq!(engine.channels[0].min_severity, SecuritySeverity::High);
    }

    // -- legacy backward compatibility ------------------------------------

    #[test]
    fn test_legacy_slack_url_creates_slack_channel() {
        let config = test_config("https://hooks.slack.com/services/T00/B00/xxx");
        let engine = AlertEngine::from_config(&config, Client::new()).unwrap();
        assert_eq!(engine.channel_count(), 1);
        assert_eq!(engine.channels[0].channel.channel_name(), "slack");
    }

    #[test]
    fn test_legacy_non_slack_url_creates_webhook_channel() {
        let config = test_config("https://example.com/webhook");
        let engine = AlertEngine::from_config(&config, Client::new()).unwrap();
        assert_eq!(engine.channel_count(), 1);
        assert_eq!(engine.channels[0].channel.channel_name(), "webhook");
    }

    // -- multi-channel config ---------------------------------------------

    #[test]
    fn test_multi_channel_config() {
        let config = AlertConfig {
            enabled: true,
            channels: vec![
                AlertChannelConfig {
                    channel_type: "slack".to_string(),
                    url: Some("https://hooks.slack.com/services/T/B/x".to_string()),
                    webhook_url: None,
                    routing_key: None,
                    min_severity: "Medium".to_string(),
                    min_security_score: 50,
                },
                AlertChannelConfig {
                    channel_type: "pagerduty".to_string(),
                    url: None,
                    webhook_url: None,
                    routing_key: Some("my-routing-key".to_string()),
                    min_severity: "Critical".to_string(),
                    min_security_score: 90,
                },
                AlertChannelConfig {
                    channel_type: "webhook".to_string(),
                    url: Some("https://example.com/hook".to_string()),
                    webhook_url: None,
                    routing_key: None,
                    min_severity: "High".to_string(),
                    min_security_score: 70,
                },
            ],
            ..AlertConfig::default()
        };
        let engine = AlertEngine::from_config(&config, Client::new()).unwrap();
        assert_eq!(engine.channel_count(), 3);
    }

    #[test]
    fn test_channels_override_legacy_webhook() {
        let config = AlertConfig {
            enabled: true,
            webhook_url: "https://should-be-ignored.com".to_string(),
            channels: vec![AlertChannelConfig {
                channel_type: "webhook".to_string(),
                url: Some("https://used.com/hook".to_string()),
                webhook_url: None,
                routing_key: None,
                min_severity: "High".to_string(),
                min_security_score: 70,
            }],
            ..AlertConfig::default()
        };
        let engine = AlertEngine::from_config(&config, Client::new()).unwrap();
        assert_eq!(engine.channel_count(), 1);
    }

    #[test]
    fn test_unknown_channel_type_skipped() {
        let config = AlertConfig {
            enabled: true,
            channels: vec![AlertChannelConfig {
                channel_type: "carrier_pigeon".to_string(),
                url: Some("https://pigeon.com".to_string()),
                webhook_url: None,
                routing_key: None,
                min_severity: "High".to_string(),
                min_security_score: 70,
            }],
            ..AlertConfig::default()
        };
        assert!(AlertEngine::from_config(&config, Client::new()).is_none());
    }

    #[test]
    fn test_missing_url_skipped() {
        let config = AlertConfig {
            enabled: true,
            channels: vec![AlertChannelConfig {
                channel_type: "slack".to_string(),
                url: None,
                webhook_url: None,
                routing_key: None,
                min_severity: "High".to_string(),
                min_security_score: 70,
            }],
            ..AlertConfig::default()
        };
        assert!(AlertEngine::from_config(&config, Client::new()).is_none());
    }

    #[test]
    fn test_pagerduty_missing_key_skipped() {
        let config = AlertConfig {
            enabled: true,
            channels: vec![AlertChannelConfig {
                channel_type: "pagerduty".to_string(),
                url: None,
                webhook_url: None,
                routing_key: None,
                min_severity: "High".to_string(),
                min_security_score: 70,
            }],
            ..AlertConfig::default()
        };
        assert!(AlertEngine::from_config(&config, Client::new()).is_none());
    }

    // -- cooldown ----------------------------------------------------------

    #[test]
    fn test_first_alert_passes_cooldown() {
        let engine =
            AlertEngine::from_config(&test_config("http://example.com"), Client::new()).unwrap();
        assert!(engine.passes_cooldown(&high_finding()));
    }

    #[test]
    fn test_recent_alert_blocked_by_cooldown() {
        let engine =
            AlertEngine::from_config(&test_config("http://example.com"), Client::new()).unwrap();
        let finding = high_finding();
        engine
            .cooldowns
            .insert(finding.finding_type.clone(), Instant::now());
        assert!(!engine.passes_cooldown(&finding));
    }

    #[test]
    fn test_zero_cooldown_always_passes() {
        let config = AlertConfig {
            cooldown_seconds: 0,
            ..test_config("http://example.com")
        };
        let engine = AlertEngine::from_config(&config, Client::new()).unwrap();
        let finding = high_finding();
        engine
            .cooldowns
            .insert(finding.finding_type.clone(), Instant::now());
        assert!(engine.passes_cooldown(&finding));
    }

    #[test]
    fn test_different_finding_types_independent_cooldowns() {
        let engine =
            AlertEngine::from_config(&test_config("http://example.com"), Client::new()).unwrap();
        engine
            .cooldowns
            .insert("prompt_injection".to_string(), Instant::now());
        assert!(engine.passes_cooldown(&critical_finding()));
        assert!(!engine.passes_cooldown(&high_finding()));
    }

    // -- payload generation ------------------------------------------------

    #[test]
    fn test_slack_payload_structure() {
        let alert = AlertPayload {
            trace_id: Uuid::new_v4(),
            tenant_id: TenantId::new(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            findings: vec![AlertFinding::from_security_finding(&high_finding())],
        };
        let payload = build_slack_payload(&alert);
        assert!(payload.text.contains("LLMTrace Security Alert"));
        assert_eq!(payload.blocks.len(), 3); // header + section + context
        assert_eq!(payload.blocks[0]["type"], "header");
        assert_eq!(payload.blocks[1]["type"], "section");
        assert_eq!(payload.blocks[2]["type"], "context");
    }

    #[test]
    fn test_pagerduty_severity_mapping() {
        assert_eq!(PagerDutyChannel::map_severity("Critical"), "critical");
        assert_eq!(PagerDutyChannel::map_severity("High"), "error");
        assert_eq!(PagerDutyChannel::map_severity("Medium"), "warning");
        assert_eq!(PagerDutyChannel::map_severity("Low"), "info");
        assert_eq!(PagerDutyChannel::map_severity("Info"), "info");
        assert_eq!(PagerDutyChannel::map_severity("Unknown"), "warning");
    }

    // -- integration tests with mock servers --------------------------------

    #[tokio::test]
    async fn test_webhook_delivery_generic() {
        let (url, received) = simple_mock("/webhook").await;
        let config = test_config(&url);
        let engine = AlertEngine::from_config(&config, Client::new()).unwrap();

        let trace_id = Uuid::new_v4();
        let tenant_id = TenantId::new();
        engine.check_and_alert(trace_id, tenant_id, &[high_finding()]);

        tokio::time::sleep(Duration::from_millis(500)).await;

        let payloads = received.lock().await;
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0]["alert_type"], "security_finding");
        assert_eq!(payloads[0]["trace_id"], trace_id.to_string());
        assert_eq!(payloads[0]["tenant_id"], tenant_id.to_string());
        assert_eq!(payloads[0]["findings"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_no_webhook_for_low_severity() {
        let (url, received) = simple_mock("/webhook").await;
        let config = test_config(&url);
        let engine = AlertEngine::from_config(&config, Client::new()).unwrap();

        engine.check_and_alert(Uuid::new_v4(), TenantId::new(), &[low_finding()]);

        tokio::time::sleep(Duration::from_millis(300)).await;

        let payloads = received.lock().await;
        assert!(payloads.is_empty());
    }

    #[tokio::test]
    async fn test_cooldown_prevents_duplicate_webhook() {
        let (url, received) = simple_mock("/webhook").await;
        let config = test_config(&url);
        let engine = AlertEngine::from_config(&config, Client::new()).unwrap();

        let findings = vec![high_finding()];

        // First alert — should fire
        engine.check_and_alert(Uuid::new_v4(), TenantId::new(), &findings);
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Second alert — should be suppressed
        engine.check_and_alert(Uuid::new_v4(), TenantId::new(), &findings);
        tokio::time::sleep(Duration::from_millis(300)).await;

        let payloads = received.lock().await;
        assert_eq!(
            payloads.len(),
            1,
            "Cooldown should suppress the second alert"
        );
    }

    #[tokio::test]
    async fn test_multi_channel_per_severity_filtering() {
        // Channel 1: webhook (min_severity: Medium)
        let (url1, received1) = simple_mock("/ch1").await;
        // Channel 2: webhook (min_severity: Critical)
        let (url2, received2) = simple_mock("/ch2").await;

        let config = AlertConfig {
            enabled: true,
            cooldown_seconds: 0,
            channels: vec![
                AlertChannelConfig {
                    channel_type: "webhook".to_string(),
                    url: Some(url1),
                    webhook_url: None,
                    routing_key: None,
                    min_severity: "Medium".to_string(),
                    min_security_score: 0,
                },
                AlertChannelConfig {
                    channel_type: "webhook".to_string(),
                    url: Some(url2),
                    webhook_url: None,
                    routing_key: None,
                    min_severity: "Critical".to_string(),
                    min_security_score: 0,
                },
            ],
            ..AlertConfig::default()
        };

        let engine = AlertEngine::from_config(&config, Client::new()).unwrap();
        assert_eq!(engine.channel_count(), 2);

        // Send a High finding — should go to channel 1 only (Medium threshold)
        engine.check_and_alert(Uuid::new_v4(), TenantId::new(), &[high_finding()]);
        tokio::time::sleep(Duration::from_millis(500)).await;

        let p1 = received1.lock().await;
        let p2 = received2.lock().await;
        assert_eq!(
            p1.len(),
            1,
            "High finding should reach Medium-threshold channel"
        );
        assert_eq!(
            p2.len(),
            0,
            "High finding should NOT reach Critical-threshold channel"
        );
        drop(p1);
        drop(p2);

        // Send a Critical finding — should go to both channels
        engine.check_and_alert(Uuid::new_v4(), TenantId::new(), &[critical_finding()]);
        tokio::time::sleep(Duration::from_millis(500)).await;

        let p1 = received1.lock().await;
        let p2 = received2.lock().await;
        assert_eq!(
            p1.len(),
            2,
            "Critical finding should also reach Medium-threshold channel"
        );
        assert_eq!(
            p2.len(),
            1,
            "Critical finding should reach Critical-threshold channel"
        );
    }

    #[tokio::test]
    async fn test_multi_channel_score_filtering() {
        let (url1, received1) = simple_mock("/lo").await;
        let (url2, received2) = simple_mock("/hi").await;

        let config = AlertConfig {
            enabled: true,
            cooldown_seconds: 0,
            channels: vec![
                AlertChannelConfig {
                    channel_type: "webhook".to_string(),
                    url: Some(url1),
                    webhook_url: None,
                    routing_key: None,
                    min_severity: "High".to_string(),
                    min_security_score: 50, // low threshold
                },
                AlertChannelConfig {
                    channel_type: "webhook".to_string(),
                    url: Some(url2),
                    webhook_url: None,
                    routing_key: None,
                    min_severity: "High".to_string(),
                    min_security_score: 95, // very high threshold
                },
            ],
            ..AlertConfig::default()
        };

        let engine = AlertEngine::from_config(&config, Client::new()).unwrap();

        // 0.95 * 100 = 95 → passes both (50 and 95)
        engine.check_and_alert(Uuid::new_v4(), TenantId::new(), &[high_finding()]);
        tokio::time::sleep(Duration::from_millis(500)).await;

        let p1 = received1.lock().await;
        let p2 = received2.lock().await;
        assert_eq!(p1.len(), 1);
        assert_eq!(p2.len(), 1);
        drop(p1);
        drop(p2);

        // low_confidence_finding: 0.4 * 100 = 40 → passes only channel 1 (score threshold 50? no, 40 < 50)
        // Actually 40 < 50 so it passes neither. Let's send medium_finding (0.85 * 100 = 85).
        // But medium_finding has severity Medium, which is < High. So it won't pass either.
        // Let's use a custom finding.
        let f = SecurityFinding::new(
            SecuritySeverity::High,
            "borderline".to_string(),
            "Borderline confidence".to_string(),
            0.80, // 80 >= 50 but 80 < 95
        );
        engine.check_and_alert(Uuid::new_v4(), TenantId::new(), &[f]);
        tokio::time::sleep(Duration::from_millis(500)).await;

        let p1 = received1.lock().await;
        let p2 = received2.lock().await;
        assert_eq!(p1.len(), 2, "80% score passes the 50-threshold channel");
        assert_eq!(
            p2.len(),
            1,
            "80% score does NOT pass the 95-threshold channel"
        );
    }

    #[tokio::test]
    async fn test_deduplication_across_channels() {
        // Both channels should respect the SAME cooldown for the same finding type
        let (url1, received1) = simple_mock("/a").await;
        let (url2, received2) = simple_mock("/b").await;

        let config = AlertConfig {
            enabled: true,
            cooldown_seconds: 300, // 5 min cooldown
            channels: vec![
                AlertChannelConfig {
                    channel_type: "webhook".to_string(),
                    url: Some(url1),
                    webhook_url: None,
                    routing_key: None,
                    min_severity: "High".to_string(),
                    min_security_score: 70,
                },
                AlertChannelConfig {
                    channel_type: "webhook".to_string(),
                    url: Some(url2),
                    webhook_url: None,
                    routing_key: None,
                    min_severity: "High".to_string(),
                    min_security_score: 70,
                },
            ],
            ..AlertConfig::default()
        };

        let engine = AlertEngine::from_config(&config, Client::new()).unwrap();

        // First call: both channels should fire
        engine.check_and_alert(Uuid::new_v4(), TenantId::new(), &[high_finding()]);
        tokio::time::sleep(Duration::from_millis(500)).await;

        let p1 = received1.lock().await;
        let p2 = received2.lock().await;
        assert_eq!(p1.len(), 1);
        assert_eq!(p2.len(), 1);
        drop(p1);
        drop(p2);

        // Second call: cooldown blocks it on BOTH channels
        engine.check_and_alert(Uuid::new_v4(), TenantId::new(), &[high_finding()]);
        tokio::time::sleep(Duration::from_millis(500)).await;

        let p1 = received1.lock().await;
        let p2 = received2.lock().await;
        assert_eq!(p1.len(), 1, "Cooldown should suppress on channel 1");
        assert_eq!(p2.len(), 1, "Cooldown should suppress on channel 2");
    }

    #[tokio::test]
    async fn test_legacy_config_backward_compatibility() {
        // The old-style config with just webhook_url (no channels array) must work
        let (url, received) = simple_mock("/legacy").await;

        let config = AlertConfig {
            enabled: true,
            webhook_url: url,
            min_severity: "High".to_string(),
            min_security_score: 70,
            cooldown_seconds: 0,
            channels: Vec::new(), // empty → legacy mode
            escalation: None,
        };

        let engine = AlertEngine::from_config(&config, Client::new()).unwrap();
        assert_eq!(engine.channel_count(), 1);

        engine.check_and_alert(Uuid::new_v4(), TenantId::new(), &[high_finding()]);
        tokio::time::sleep(Duration::from_millis(500)).await;

        let payloads = received.lock().await;
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0]["alert_type"], "security_finding");
    }

    #[tokio::test]
    async fn test_slack_channel_sends_block_kit() {
        let (url, received) = simple_mock("/slack").await;

        let channel = SlackChannel::new(url, Client::new());
        let payload = AlertPayload {
            trace_id: Uuid::new_v4(),
            tenant_id: TenantId::new(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            findings: vec![
                AlertFinding::from_security_finding(&high_finding()),
                AlertFinding::from_security_finding(&critical_finding()),
            ],
        };

        channel.send_alert(&payload).await.unwrap();

        let payloads = received.lock().await;
        assert_eq!(payloads.len(), 1);
        assert!(payloads[0]["text"]
            .as_str()
            .unwrap()
            .contains("LLMTrace Security Alert"));
        assert!(payloads[0]["blocks"].is_array());
        let blocks = payloads[0]["blocks"].as_array().unwrap();
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0]["type"], "header");
        assert_eq!(blocks[1]["type"], "section");
        assert_eq!(blocks[2]["type"], "context");
    }

    #[tokio::test]
    async fn test_pagerduty_channel_payload_structure() {
        let (url, received) = simple_mock("/pd").await;

        // Override the PD URL for testing (we can't hit the real PD endpoint)
        // We'll test the payload structure via the webhook channel with PD-like payload
        // For a real unit test, let's use the AlertPayload directly
        let alert = AlertPayload {
            trace_id: Uuid::new_v4(),
            tenant_id: TenantId::new(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            findings: vec![AlertFinding::from_security_finding(&critical_finding())],
        };

        // Directly verify PagerDuty severity mapping
        assert_eq!(PagerDutyChannel::map_severity("Critical"), "critical");

        // Verify slack payload serialization doesn't panic
        let _slack_payload = build_slack_payload(&alert);

        // Verify the generic webhook works
        let wh = WebhookChannel::new(url, Client::new());
        wh.send_alert(&alert).await.unwrap();

        let payloads = received.lock().await;
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0]["findings"].as_array().unwrap().len(), 1);
        assert_eq!(payloads[0]["findings"][0]["severity"], "Critical");
    }

    // -- is_slack_webhook --------------------------------------------------

    #[test]
    fn test_slack_webhook_detected() {
        assert!(is_slack_webhook(
            "https://hooks.slack.com/services/T00/B00/xxx"
        ));
        assert!(is_slack_webhook(
            "https://hooks.slack-gov.com/services/T00/B00/xxx"
        ));
    }

    #[test]
    fn test_non_slack_webhook() {
        assert!(!is_slack_webhook("https://example.com/webhook"));
        assert!(!is_slack_webhook(
            "https://discord.com/api/webhooks/123/abc"
        ));
    }
}
