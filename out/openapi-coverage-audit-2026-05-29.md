# OpenAPI Coverage Audit — 2026-05-29

Scope: `crates/llmtrace-proxy/src/` (excludes `/v1/*` proxy passthrough, debug endpoints, pure middleware).

## Gap found and fixed

`GET /api/v1/stats/global` (`crate::api::get_global_stats`) carried a `#[utoipa::path]` annotation
but was absent from `ApiDoc::paths(...)` in `openapi.rs`. Added to the registry.

## Full endpoint status

| Method | Path | Handler | Annotated | In ApiDoc |
|--------|------|---------|-----------|-----------|
| GET | /health | proxy::health_handler | no | n/a (intentionally excluded) |
| GET | /metrics | metrics::metrics_handler | no | n/a (intentionally excluded) |
| POST | /api/v1/auth/keys | auth::create_api_key | yes | yes |
| GET | /api/v1/auth/keys | auth::list_api_keys | yes | yes |
| DELETE | /api/v1/auth/keys/:id | auth::revoke_api_key | yes | yes |
| GET | /api/v1/audit | audit_api::list_audit_events | yes | yes |
| GET | /api/v1/config/live | api::get_live_config | yes | yes |
| GET | /api/v1/config/features | feature_flags_api::get_features | yes | yes |
| PUT | /api/v1/config/features | feature_flags_api::bulk_update_features | yes | yes |
| PUT | /api/v1/config/features/:feature | feature_flags_api::update_feature | yes | yes |
| GET | /api/v1/traces | api::list_traces | yes | yes |
| GET | /api/v1/traces/:trace_id | api::get_trace | yes | yes |
| POST | /api/v1/traces/:trace_id/actions | api::report_action | yes | yes |
| GET | /api/v1/spans | api::list_spans | yes | yes |
| GET | /api/v1/spans/:span_id | api::get_span | yes | yes |
| GET | /api/v1/stats | api::get_stats | yes | yes |
| GET | /api/v1/stats/global | api::get_global_stats | yes | **fixed** |
| GET | /api/v1/security/findings | api::list_security_findings | yes | yes |
| GET | /api/v1/costs/current | api::get_current_costs | yes | yes |
| GET | /api/v1/actions/summary | api::actions_summary | yes | yes |
| POST | /api/v1/tenants | tenant_api::create_tenant | yes | yes |
| GET | /api/v1/tenants | tenant_api::list_tenants | yes | yes |
| GET | /api/v1/tenants/current/token | tenant_api::get_current_tenant_token | yes | yes |
| GET | /api/v1/tenants/:id | tenant_api::get_tenant | yes | yes |
| PUT | /api/v1/tenants/:id | tenant_api::update_tenant | yes | yes |
| DELETE | /api/v1/tenants/:id | tenant_api::delete_tenant | yes | yes |
| GET | /api/v1/tenants/:id/token | tenant_api::get_tenant_token | yes | yes |
| POST | /api/v1/tenants/:id/token/reset | tenant_api::reset_tenant_token | yes | yes |
| POST | /api/v1/reports/generate | compliance::generate_report | yes | yes |
| GET | /api/v1/reports | compliance::list_reports | yes | yes |
| GET | /api/v1/reports/:id | compliance::get_report | yes | yes |
| POST | /v1/traces | otel::ingest_traces | no | n/a (OTel ingestion, out-of-scope per audit) |
| GET/DELETE/... | /v1/* | proxy::proxy_handler | no | n/a (upstream passthrough, excluded by design) |
| GET | /debug/judge/verdicts | debug::verdict_by_trace_id_handler | no | n/a (debug-flag gated, excluded) |
| GET | /debug/judge/golden_set/replay | debug::golden_set_replay_handler | no | n/a (debug-flag gated, excluded) |

## Schema spot-checks (5 handlers)

1. `api::get_global_stats` — response `body = llmtrace_core::StorageStats`. `StorageStats` derives `ToSchema`. Matches handler return type. OK.
2. `api::report_action` — `request_body = ReportActionRequest`, response `body = ReportActionResponse`. Both structs derive `ToSchema` in `api.rs`. Match handler signature `Json<ReportActionRequest>` / `Json(ReportActionResponse)`. OK.
3. `tenant_api::create_tenant` — `request_body = CreateTenantRequest`, response `body = CreateTenantResponse`. Both derive `ToSchema`. Match `Json<CreateTenantRequest>` / `Json(CreateTenantResponse)`. OK.
4. `feature_flags_api::bulk_update_features` — response verified against handler in `feature_flags_api.rs`. OK.
5. `audit_api::list_audit_events` — response `body = [llmtrace_core::AuditEvent]` (array). `AuditEvent` derives `ToSchema` in `llmtrace-core`. Matches `Json(events)` return. OK.

## Verdict

One registry gap fixed. All other documented endpoints are correctly annotated and registered.
No stale entries. No schema mismatches found in spot-checked handlers.
