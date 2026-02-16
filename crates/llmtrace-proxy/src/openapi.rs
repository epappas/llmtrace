//! OpenAPI / Swagger documentation for the LLMTrace proxy.
//!
//! This module wires existing `#[utoipa::path]` annotations into a single
//! OpenAPI document that can be served via Swagger UI.

use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

/// Adds the `api_key` security scheme referenced by `#[utoipa::path(..., security(("api_key" = [])))]`.
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "api_key",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("API key")
                    .build(),
            ),
        );
    }
}

/// Proxy API documentation.
///
/// Note: only handlers annotated with `#[utoipa::path]` are included.
#[derive(OpenApi)]
#[openapi(
    paths(
        crate::api::list_traces,
        crate::api::get_trace,
        crate::api::list_spans,
        crate::api::get_span,
        crate::api::get_stats,
        crate::api::list_security_findings,
        crate::api::get_current_costs,
        crate::api::report_action,
        crate::api::actions_summary,
        crate::auth::create_api_key,
        crate::auth::list_api_keys,
        crate::auth::revoke_api_key,
        crate::tenant_api::create_tenant,
        crate::tenant_api::list_tenants,
        crate::tenant_api::get_tenant,
        crate::tenant_api::update_tenant,
        crate::tenant_api::delete_tenant,
        crate::tenant_api::get_current_tenant_token,
        crate::tenant_api::get_tenant_token,
        crate::tenant_api::reset_tenant_token,
        crate::compliance::generate_report,
        crate::compliance::get_report,
        crate::compliance::list_reports,
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "LLMTrace Proxy", description = "LLMTrace proxy REST API")
    )
)]
pub struct ApiDoc;
