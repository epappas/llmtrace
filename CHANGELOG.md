# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security fixes

### Bug fixes

### Features

### Operational notes

## [0.3.0] - 2026-06-12

Upgrade urgency: recommended — includes dependency security fixes and
multi-tenant security hardening; no breaking API changes for proxy clients.

### Security fixes
- pyo3 0.24.2 -> 0.29.0: RUSTSEC-2026-0176 (out-of-bounds read in
  PyList/PyTuple iterators) and RUSTSEC-2026-0177 (missing Sync bound on
  new_closure) (#388).
- `/v1/*` forwarding now requires an Operator-role credential (#269), and the
  proxy substitutes the upstream provider key on forward so client-presented
  keys never reach the provider (#274).
- Tenant default API keys are minted Operator, not Admin — closes a
  cross-tenant read via scope=all.
- Dashboard `/metrics` removed from the public allow-list (#280); datamarking
  strips zero-width formatting characters (#215); transitive postcss override
  for GHSA-qx2v-qp2m-jg93.

### Features
- Multi-tenant runtime: per-tenant upstream routing with keys encrypted at
  rest, admin tenant scoping, idempotent bootstrap, catch-all tenant
  self-provisioning (no hardcoded ids), per-tenant rate-limit plumbing and a
  request-body cap.
- Tenant admin API: tenant CRUD, per-tenant traffic-token reveal/reset,
  scoped operator-key minting; audit API `GET /api/v1/audit` with a dashboard
  page (#246).
- Dashboard: admin-key login (#250), one-click SSO for portal handoff
  (#367, #368, #369), `/playground` chat panel with per-message LLMTrace
  metadata (#284, #287), dark mode by default, dedicated API-docs page (#281).
- Security analysis: zone detector + zone-aware ensemble and datamarking
  transform (IS-060), three-tier judge cascade (DeBERTa fast-judge, vLLM
  backend, runtime toggle), SafetyJudge placeholder + design spec,
  rot13/leetspeak encoding-attack detection, advisory headers + LLM-facing
  system advisory, response envelope with deduplicated findings (#83).
- E2E adversarial framework: 50-scenario corpus across 8 attack families,
  PR gate + nightly full-corpus runs with auto-PR'd reports, LLM-backed
  upstream-fell-for-it judge (#97, #98, #99, #100, #123).
- Proxy: redundant `/v1` prefix de-duplication in upstream URLs (#374),
  `X-LLMTrace-Trace-Id` honored and echoed (#91), cost tracking enabled by
  default with per-span aggregation into storage stats.

### Bug fixes
- Analysis pipeline: full analysis runs pre-forward so the advisory and
  envelope share findings; silent analyzer skips are forbidden and dropped
  traces tagged; log mode still runs analyzers (#298, #300, #311).
- Dashboard: tenant isolation end-to-end, stale tenant-selection
  reconciliation, `x-llmtrace-*` response-header forwarding, confidence
  display flooring.
- Deployment: ML-preload startup-timeout floor (#243), idempotent tenant
  bootstrap when the catch-all already exists, `sqlite` accepted as a storage
  profile alias (#249).

### Operational notes
- Releases now publish BOTH images version-tagged:
  `ghcr.io/techlab-innov/llmtrace-proxy` and
  `ghcr.io/techlab-innov/llmtrace-dashboard` as `:0.3.0` and `:latest`.
- No proxy schema or config migrations are required. Deployments pinned to
  older images are unaffected until upgraded.

## [0.2.0] - 2026-04-17

- chore: bump workspace version to 0.2.0 (6647795)
- fix(storage): replace sort_by with sort_by_key to satisfy clippy (d757169)
- Merge pull request #64 from epappas/feat/issue-42-config-handle (69c5986)
- fix(metrics): pre-initialise audit_event_dropped_total counter to zero (6364faa)
- refactor(proxy): address /github-review findings on #42 (10c7ac3)
- refactor(proxy): address second-pass review nits on #42 (70a6090)
- chore(deps): bump rustls-webpki 0.103.10 -> 0.103.12 (bfe2d7b)
- refactor(proxy): address rust + mlops review feedback on #42 (2642ea4)
- feat(proxy): feature-flag sidecar persistence, metrics, audit logs (c18561c)
- test(core): add llm_judge_enabled to ProxyConfig roundtrip fixture (2fdf5ae)
- feat(proxy): admin API for runtime feature flags (0074e00)
- feat(proxy): feature_flags module with validation and field mapping (3562f8d)
- feat(proxy): always-construct cost+rate limiter; wire ensemble runtime (94c33ec)
- feat(security): add EnsembleRuntimeHandle for runtime flag toggles (d63803d)
- feat(core): add ProxyConfig.llm_judge_enabled store-only flag (0964874)
- style: apply cargo fmt (9445f7a)
- feat(proxy): introduce ConfigHandle for runtime-mutable config (919a198)
- fix(dashboard): bump next to 15.5.15 to patch GHSA-q4gf-8mx6-v5v3 (0b1cb80)
- docs(benchmarks): extend full e2e local run progress log to 59% (c5e161a)
- Merge pull request #59 from epappas/feat/issue-45-multi-provider-deploy (4609db5)
- feat(deploy): add helm and compose deployment assets (5e12b35)
- Merge pull request #58 from epappas/feature/action-router-41 (0bf17a6)
- ci: upgrade GitHub actions to Node 24 (773c7c4)
- Merge pull request #57 from epappas/feature/action-router-41 (ede8cb9)
- fix(action-router): complete issue 41 acceptance criteria (585b875)
- Merge pull request #56 from epappas/feature/action-router-41 (25c2017)
- fix(ci): remove unused action router test helper (248942f)
- feat: Action Router/Orchestrator (#41) (fce0c07)
- Merge pull request #55 from epappas/fix/security-audit (d53f341)
- fix(docker): upgrade alpine base packages to resolve zlib vulnerabilities (8b50ecd)
- fix(ci): bump compromised trivy-action to v0.35.0 in release pipeline (68a5042)
- ci: add security-audit job for npm and cargo (60a9f0f)
- fix(security): resolve dependabot alerts and audit warnings across node.js and rust (26f21f0)
- Merge pull request #53 from epappas/dependabot/npm_and_yarn/dashboard/lodash-4.18.1 (3e3d9bd)
- Merge pull request #52 from epappas/dependabot/npm_and_yarn/crates/llmtrace-nodejs/handlebars-4.7.9 (f4048d7)
- Merge pull request #54 from epappas/dependabot/npm_and_yarn/crates/llmtrace-nodejs/picomatch-2.3.2 (d272443)
- Merge pull request #51 from epappas/dependabot/npm_and_yarn/dashboard/multi-bf05dc1ecf (f5e3c51)
- chore(deps-dev): bump picomatch in /crates/llmtrace-nodejs (609b530)
- chore(deps): bump lodash from 4.17.23 to 4.18.1 in /dashboard (a856c48)
- Merge pull request #50 from epappas/dependabot/npm_and_yarn/dashboard/next-15.5.14 (2c15755)
- Merge pull request #48 from epappas/dependabot/cargo/rustls-webpki-0.103.10 (e656b39)
- chore(deps-dev): bump handlebars in /crates/llmtrace-nodejs (7f9c7a4)
- chore(deps): bump picomatch in /dashboard (3d8bbc3)
- chore(deps): bump next from 15.5.12 to 15.5.14 in /dashboard (f1a3f18)
- Merge pull request #49 from epappas/dependabot/npm_and_yarn/dashboard/flatted-3.4.2 (150a216)
- chore(deps-dev): bump flatted from 3.3.3 to 3.4.2 in /dashboard (239ec0a)
- chore(deps): bump rustls-webpki from 0.103.9 to 0.103.10 (020d0b9)
- docs: add scientific report for ensemble evaluation (e37f032)
- docs: update benchmarks, model token limits, and changelog for truncation fix (a78ec59)
- docs(evidence): add SLA evidence report and basilica deployment artifacts (5062ae1)
- fix(security): truncate ML tokens for InjecGuard/PromptGuard and correct corpus labels (3432253)
- Merge pull request #47 from epappas/dependabot/cargo/lz4_flex-0.11.6 (8d96cc0)
- chore(deps): bump lz4_flex from 0.11.5 to 0.11.6 (3274121)
- fix(core): UTF-8 safe truncation and DRY up truncate logic (9bed830)
- feat(proxy): parse SSE tool call deltas for streaming responses (425d00f)
- feat(security): add ML long input defense with sliding window inference (#23) (6966648)
- fix(ci): update Trivy action and align proxy port to 8080 (c1ed14b)
- feat(proxy): add boundary token injection defense (86d5fdc)
- Merge pull request #38 from epappas/dependabot/npm_and_yarn/crates/llmtrace-nodejs/minimatch-3.1.5 (ec317f8)
- Merge pull request #36 from epappas/dependabot/npm_and_yarn/dashboard/multi-770cfcd984 (e05564f)
- chore(deps): bump minimatch in /crates/llmtrace-nodejs (8db835f)
- Merge pull request #37 from epappas/feat/deploy-and-docker-hardening (e63d439)
- docs(security): add analyzers technical breakdown (5655952)
- feat(deploy): add Basilica deployment scripts (91ed060)
- feat(proxy): add LLMTRACE_ML_CACHE_DIR env var override (31c03a5)
- fix(docker): harden container user setup and model cache (a5f824a)
- chore(deps): bump minimatch in /dashboard (e489c3c)
- Merge pull request #35 from epappas/feat/llm-jailbreaks-regression-patterns (1865d66)
- fix: apply cargo fmt formatting (1d5935c)
- feat(security): add LLM-Jailbreaks regression samples and format manipulation detection (f0013af)
- Merge pull request #32 from epappas/feat/bench-dataset-expansion (35369f7)
- fix(ci): resolve clippy redundant closure and skip missing datasets (b3cabd0)
- fix: apply cargo fmt formatting fixes (28a0eff)
- benchmarks: archive results and JSONL exports 2026-02-24 (2259c00)
- feat(benchmarks): add JSONL export for datasets and DB traces (6424dea)
- feat(benchmarks): add full-dataset mode to proxy stress test (a8f1606)
- feat(security): additive-only auxiliary architecture for IG/PG (5209e09)
- benchmarks: archive results snapshot 2026-02-20 (49234ca)
- feat(benchmarks): add 10 new external evaluation datasets (2dda503)
- Merge pull request #34 from epappas/Refactoring (b120912)
- Merge pull request #33 from epappas/feat/status-health-metrics (6e58219)
- fix(e2e): stabilize dashboard lifecycle and costs assertions (b5760ca)
- fix(e2e): stabilize dashboard lifecycle and costs assertions (d9d527b)
- feat: add dashboard status page and lifecycle resilience updates (b785c7e)
- Merge pull request #31 from epappas/fix/dashboard-auth-injection (90acf03)
- Merge pull request #30 from epappas/fix/settings-page-404 (54e120b)
- Merge pull request #29 from epappas/fix/proxy-env-parsing (18cec0d)
- fix: resolve unused auth binding in global stats handler (24240d7)
- fix: resolve unused auth binding in global stats handler (2bd9402)
- fix(ci): format sqlite storage query for fmt check (1ba198b)
- fix(ci): format sqlite storage query for fmt check (44c6bed)
- merge handler fix (05e3bba)
- merge handler fix (c36c3c1)
- fix(api): use Extensions extractor in get_global_stats (50ba50a)
- merge style fixes (ae466d5)
- merge style fixes (c69c925)
- style: fix formatting in global stats implementations (5582c09)
- merge fixes into feat/global-stats (dcfbaf3)
- merge fixes into fix/settings-page-404 (c9efd74)
- merge feat/global-stats into fix/dashboard-auth-injection (cdb8ada)
- Merge pull request #26 from epappas/feat/global-stats (ed1b2a5)
- fix(dashboard): correct live config path in Settings page (8873300)
- fix(dashboard): implement secure server-side proxy with auth injection (6ad0147)
- feat(api): implement cluster-wide global stats (cc6c824)
- fix(proxy): support '1' and 'true' for boolean env vars (f328b27)
- changelog: update for v0.1.5 (f5ee5ef)
- Merge pull request #22 from epappas/fix-metrics-001 (33d9412)
- fix(dashboard): map trace detail metrics to backend fields (5ab368c)
- Merge pull request #21 from epappas/Add-api-route-001 (df47899)
- feat: expose live proxy config and render current settings (78768af)

## [Unreleased]

### Fixed

- InjecGuard and PromptGuard crashed on inputs longer than 512 tokens with `narrow invalid args: start + len > dim_len`. Both models now read `max_position_embeddings` from the model's config.json and truncate token sequences before calling `model.forward()`. PIGuard inherits the fix via InjecGuard delegation.

### Changed

- `advbench_harmful` (520 samples) and the malicious subset of `jailbreakbench` (100 samples) relabeled from `category: jailbreak` to `category: harmful_content`. These are direct harmful-topic requests with no injection pattern; they are now excluded from injection-detection accuracy metrics and reported in a separate section of the benchmark output.
- Benchmark metrics updated: 87.9% accuracy, 89.1% F1 on 199 injection-scope samples (up from 87.6% / 86.9% on 153 samples).

## [0.1.5] - 2026-02-19

- chore(release): align workspace version to 0.1.5 (68b1444)
- fix(ci): gate pypi upload on wheel build success (c5fcd82)
- Merge pull request #20 from epappas/dependabot/github_actions/dot-github/workflows/aquasecurity/trivy-action-0.34.0 (1e9d5a6)
- chore(deps): bump aquasecurity/trivy-action in /.github/workflows (c9a1d28)
- Merge pull request #19 from epappas/feat/ubuntu-24-04-release-runner (0a61faf)
- fix(ci): skip existing files when publishing to pypi (459e2ca)
- ci: move release binary runner to ubuntu 24.04 (d5aa9ec)
- Merge pull request #18 from epappas/Dash-002 (8b64f5e)
- feat(dashboard): expand guide snapshots with subpages and report viewer (d3d886f)
- Merge remote-tracking branch 'origin/main' into dash002-sync (7032623)
- changelog: update for v0.1.4 (a414ef1)
- changelog: update for v0.1.4 (1740fcf)
- feat(dashboard): add guide page and e2e feature gap coverage (6e69d66)

## [0.1.4] - 2026-02-17

- fix(release): use ubuntu-22.04 for portable Linux binary (7f4ccda)
- fix(release): add musl C++ compiler for static Linux binary build (92020c2)
- release: v0.1.4 (acc1ee3)
- fix(release): build static Linux binary with musl target (9ee1885)
- feat(scripts): add one-line installer script (a13a376)
- fix(docs): add missing --features ml flag, HEALTHCHECK, and GHCR image path (4b6fd68)
- refactor(scripts): rename bump-version.sh to release.sh (32a6a25)
- docs(guides): add release runbook (41a814a)
- changelog: update for v0.1.3 (972ad28)
- changelog: update for v0.1.2 (bbeed06)
- docs: update install instructions with cargo/pip/docker references (36626ea)

## [0.1.3] - 2026-02-17

- release: v0.1.3 (f7dfa0f)
- fix(release): rename PyPI package to llmtracing (llmtrace taken) (b2cd3d4)

## [0.1.1] - 2026-02-17

- fix(ci): pin python interpreter for aarch64 wheels, resilient job deps (abab87f)
- fix(ci): handle already-published crates, pin Python 3.12 for maturin (cb9780f)
- fix(ci): use working-directory instead of manifest-path for maturin (22032ed)
- fix(ci): install protoc in test and build jobs (5609937)
- release: v0.1.1 (61a2e9e)
- ci: add PyPI publish, proxy on crates.io, and binary release assets (d10ead1)
- ci: release pipeline with Docker multi-arch, crates.io publish, and changelog (79b0dc2)
- docs: add ML/security docs, guides, fix broken links and API paths (b2b0c9c)
- docs: add open-source governance files and polish repo presentation (917021f)
- fix(benchmarks): use spans API for complete stress test matching (a793024)
- Merge pull request #17 from epappas/feat/e2e-accuracy-optimization (0bdb14c)
- fix(ci): apply cargo fmt formatting (a5fbe7a)
- Merge pull request #16 from epappas/dashboard-001 (69ed36f)
- feat(dashboard): embed swagger ui in settings (12eda6c)
- Merge remote-tracking branch 'origin/main' into dashboard-001 (efbab2b)
- feat(proxy): add swagger ui and openapi docs (9b0a01b)
- docs(benchmarks): update stress test results to 87.6% accuracy (36d7ce2)
- feat(ensemble): add high-precision voting bypass and auxiliary score capping (1b51ce1)
- feat(security): add regex patterns, encoding decoders, and hex evasion detection (0afbb54)
- Merge pull request #15 from epappas/feat/e2e-accuracy-optimization (72a78ed)
- feat(enforcement): add pre-request security enforcement with configurable block/flag/log modes (1b46cd7)
- docs(benchmarks): update stress test results after ML-032/IS-070/ML-034 (adeea5c)
- feat(security): add short-input scaling, shell injection patterns, encoding preprocessor (da6e387)
- Merge pull request #14 from epappas/feat/e2e-accuracy-optimization (a62f424)
- fix(ci): replace manual modulo with is_multiple_of (10acf47)
- fix(ci): resolve clippy redundant closure warning (94581af)
- fix(ci): apply cargo fmt and update stress test results (eadbdae)
- docs: update roadmap with E2E stress test results and ML work plan (8866ef3)
- docs(benchmarks): add experiment results and analysis artifacts (ec28ae6)
- feat(benchmarks): add experiment framework and stress test scripts (7e61dfb)
- fix(dashboard): align field names and add API proxy rewrites (708d6c4)
- feat(security): add classify_raw to ML detectors (4a8e7d6)
- fix(proxy): strip role prefixes and gzip for security analysis (768f85c)
- feat(security): wire operating points, thresholds, and over-defence (c109643)
- chore: add .next/ to gitignore (977176f)
- Merge pull request #13 from epappas/dashboard-001 (4c8e49b)
- fix(e2e): make tenant persistence test robust (4d05ebe)
- fix(ci): avoid duplicate tenant api_token in postgres tests (4e3b8db)
- fix: stabilize migrations and e2e (b9c01bc)
- feat(openapi): integrate swagger and update API endpoints, enrich spans with monitoring scope (6cced4b)
- feat(openapi): correctly applied all ToSchema derives and schema attributes in llmtrace-core (3b8b952)
- fix(openapi): final corrections to ToSchema derives and format attributes in llmtrace-core (1101bd0)
- fix(openapi): corrected ToSchema derives and format attributes in llmtrace-core (aab5b73)
- fix(openapi): implement ToSchema for Uuid, DateTime<Utc>, and serde_json::Value (66ee2aa)
- fix: bind state to compliance report form inputs (ebaa163)
- fix: resolve CI failures (formatting, clippy, test adjustments) (f985052)
- feat: improve compliance report readability with Print support and better matching (4f9ee59)
- feat: enhance compliance report visibility and add download feature (6a56173)
- fix: resolve storage panic due to JSONB type mismatch in compliance reports (bafc29f)
- fix: correctly handle CORS by making it outermost layer and allowing OPTIONS in auth (86221cd)
- fix: ensure CORS headers are present on all responses by reordering layers (ed71874)
- fix: address review feedback on tenant isolation, auth, and schema (23d2539)
- feat: implement multi-tenant isolation, RBAC, per-tenant config, and compliance reporting (0e652fb)
- docs: update benchmark results (9b86d9e)
- fix: resolve dashboard trace visibility and enforce strict tenant identification (b6646b5)
- Merge pull request #12 from epappas/performace_test (ccd5bd3)
- feat(perf): add e2e overhead benchmark script and docs (6cf52c2)
- docs: update benchmark results for EV-008/EV-019/EV-021 suites (dd88cc9)
- feat(benchmarks): add HPI approx (EV-008), Tensor Trust (EV-019), Jackhhao (EV-021) eval suites (1a07b9e)
- Merge pull request #11 from epappas/minor-updates (c26041f)
- fix(docker): use rust:alpine for apk (e312c4f)
- fix(benchmarks): raise BIPIA max_fpr threshold for regex baseline (5208a31)
- fix(ci): run benchmarks with regex-only analyzer (04c2949)
- chore(docker): use latest base images (2371afb)
- refactor(security): group correlated DeBERTa detectors into single vote slot (903ef74)
- docs: update benchmark results and TODO for ML-004/EV-018 (0f7ecb0)
- fix(ci): remove unsupported --all-features from cargo deny (c47a676)
- feat(benchmarks): add transfer attack resistance eval (EV-018) (ccfc27f)
- feat(security): add PIGuard model integration (ML-004) (d0e1d54)
- feat(security): add InjecGuard to ensemble with majority voting (ML-006) (d11441d)
- Merge pull request #10 from epappas/Dashboard-changes (539dc9d)
- chore(ci): bump trivy-action (92f4fc9)
- chore(ci): bump codeql-action to v4 (29c43c6)
- fix(ci): harden coverage and e2e summaries (525b332)
- fix(ci): fix coverage summary script (0895622)
- style: rustfmt (fdc4c99)
- Merge remote-tracking branch 'origin/main' into Dashboard-changes (4e7bf1b)
- fix(ci): generate valid proxy config for e2e (4b6c313)
- fix(security,benchmarks): harden regression gates, training API, and data pipeline (e0a2558)
- docs: update TODO.md and gitignore for training pipeline (b7e5b22)
- feat(benchmarks): add fusion classifier training pipeline (ML-001) (e544630)
- feat(security): add training API to FusionClassifier (62b07e9)
- refactor(benchmarks): consolidate external suite runners into table-driven dispatch (61ce3ea)
- chore(benchmarks): pin dataset source commits for reproducibility (bd30c22)
- chore(benchmarks): add v2 English-only evaluation datasets (53b395e)
- fix(e2e): wait longer for proxy in CI (d5ad327)
- fix(ci): fix coverage summary script (af58c0d)
- ci: add coverage and e2e summaries (2fc84b4)
- fix(ci): avoid secrets context in expressions (f70c058)
- fix(ci): skip codecov upload without token and generate e2e config (33b66cf)
- chore(proxy): allow disabling ML analyzer preload via env (3a2e8a5)
- test(dashboard): stabilize playwright e2e (72a977f)
- chore(dashboard): bump next/react and add eslint config (68d59d2)
- ci: integrate playwright e2e tests into github actions pipeline (5cdbe63)
- test: strengthen Sidebar persistence test with dynamic tenant creation (a17d6bf)
- fix: update trace details test selector for Radix UI tabs (436f04b)
- test: implement robust tenant cleanup in e2e suite (f4bcb61)
- fix: finalize dashboard stability and sidebar persistence (51eab62)
- fix: apply ON DELETE CASCADE migration and stabilize tests (30ab866)
- test: finalized E2E suite with cache-busting and robust selectors (9d550d6)
- test: refine Playwright selectors and timeouts for stability (bc69e84)
- test: refine Playwright selectors and timeouts for stability (dae7637)
- test: enhance E2E suite reliability and finalize dashboard features (2246fc9)
- feat: modernize dashboard with Next.js 15, multi-tenant selection, global stats, and E2E tests (6710c72)
- chore(benchmarks): update results with new evaluation suites (5811309)
- chore(benchmarks): add external evaluation dataset files (b1a7ee6)
- feat(benchmarks): add suite runners and regression gates for 5 datasets (9bb89cc)
- feat(benchmarks): add 5 external dataset downloaders and loaders (3558adc)
- chore: update Cargo.lock for cuda/metal dependencies (f9fd36f)
- feat(security): add GPU device selection for ML detectors (2ac0eac)
- feat(examples): add Python security testing and comprehensive attack catalog (5294408)
- feat(security): add CyberSecEval2 per-category runner and fix ML analyzer loading (bfaa8ef)
- Merge pull request #5 from epappas/dependabot/npm_and_yarn/dashboard/next-15.5.10 (eadea58)
- Merge pull request #7 from geopolitis/feat/ci-coverage-llvm-cov-codecov-v2 (014045c)
- fix(benchmarks): skip ML analyzers that silently fall back to regex (ab6b724)
- ci: skip codecov upload on fork PRs and use token (132ce4f)
- docs: add 5 research paper breakdowns for prompt injection defenses (4d01421)
- docs: fix 3 stale references in DMPI architecture docs (525d0c4)
- chore(benchmarks): update benchmark results with CyberSecEval2 suite (28d2101)
- feat(benchmarks): add CyberSecEval 2 prompt injection evaluation (EV-006) (7ce0cf9)
- ci: add llvm-cov and codecov coverage reporting (76fd63a)
- fix: resolve cargo fmt formatting in otel.rs (32b8409)
- feat(benchmarks): add 3 external HuggingFace evaluation datasets (EV-011/012/013) (530a068)
- feat(security): rename finding types to paper is_* convention (DMPI-006) (31ecc48)
- docs: fix 3 priority mismatches and 2 cross-reference gaps in Agent-as-a-Proxy docs (dd49d38)
- feat(benchmarks): add CI regression gate with benchmark binary and thresholds (EV-009) (b15f4f0)
- feat(config): make Ensemble the default analyzer by enabling ml_enabled (45bcb87)
- feat(security): lower repetition threshold to >=3 per DMPI-PMHFE paper (DMPI-004) (ca89a91)
- fix: resolve all clippy warnings across workspace (d0d2456)
- feat(security): replace 15 mixed features with 10 binary per DMPI-PMHFE paper (7e20bb9)
- docs: fix 6 cross-reference gaps found in audit (dad616f)
- docs: add Agent-as-a-Proxy defense feature IDs with validation fixes (4dcfa17)
- docs: add Agent-as-a-Proxy research breakdown and cross-references (62d6ec9)
- docs: add missing Source PDF refs to BIPIA and CyberSecEval 2 breakdowns (c01a599)
- docs: add 3 missing papers to Section 6 index, download self-distillation PDF (7efcfb1)
- docs: add CyberSecEval 2 paper PDF (arXiv 2404.13161) (f81d822)
- docs: add BIPIA paper PDF (arXiv 2312.14197) (4bfb5e9)
- docs: add BIPIA research breakdown and cross-references (a8a79ae)
- feat(security): implement DMPI-002 collapse fusion classifier to 2 FC layers (4e76694)
- docs: add CyberSecEval 2 research breakdown and cross-references (279a9ec)
- feat(security): implement DMPI-001 average pooling for fusion embeddings (f051cba)
- docs: audit DMPI-PMHFE alignment, track 6 architecture deviations (e297137)
- chore(deps): bump next from 14.2.35 to 15.5.10 in /dashboard (41b54f2)
- docs: update architecture and getting-started guides (f742f98)
- chore: update security audits and deps (672df31)
- ci: install audit and deny tools (723e8ee)
- chore: enforce fmt check in just (a0765f2)
- docs: add implementation plan template and fpr report (802bd6d)
- benchmarks: add fpr calibration bench (22ddcf2)
- chore: ignore root todo (a5b4fe1)
- chore: update Justfile (3f82dd0)
- fix: update multi-model ensemble (027e1f1)
- docs: mark NotInject tasks as complete (2fe89e9)
- benchmarks: complete NotInject dataset and runner (5f3c141)
- docs: sync roadmap and todo audit statuses (f89a0c3)
- docs(research): add defense pipeline and PDFs (2ee8ea4)
- docs(project): update agent and loop docs (e2f0a61)
- feat(security): add multi-signal monitors (c198a70)
- docs: add Self-Distillation (SDFT) paper to research — continual learning for model training (cf2e617)
- docs: mark ML-002, ML-003, ML-006 complete in TODO.md (a000a56)
- feat(security): model ensemble diversification — InjecGuard, PromptGuard2, multi-model voting (Loop 8) (10a2369)
- feat(security): add FPR calibration framework with over-defense tracking (0307201)
- docs: comprehensive implementation TODO with RALPH loops from FEATURE_ROADMAP gap analysis (b79eda8)
- docs: update TODO — Loop 12 complete (0a0aa7b)
- feat(security): advanced prompt injection — synonym expansion, stemming, P2SQL, header attacks (ec6a69a)
- docs: update TODO — Loop 9 complete (60ce6f0)
- feat(security): action-selector policy enforcement and context minimization (89ba304)
- docs: update TODO — Loop 7 complete (ba38e99)
- feat(security): tool-boundary firewalling — input minimizer, output sanitizer, format constraints (9f22659)
- docs: update TODO — Loop 6 complete (76b2773)
- feat(security): context window flooding detection (OWASP LLM10) (9997962)
- docs: update TODO — Loops 4-5 complete (8ab851d)
- feat(security): tool registry and action-type rate limiting (eae4ca3)
- chore: remove placeholder benchmark stubs + update TODO with Loop 4 completion (56a218d)
- feat(security): canary token system for system prompt leakage detection (5b43d93)
- docs: update TODO — Loop 2 complete (c4b3e46)
- feat(benchmarks): NotInject over-defense evaluation + 3D metrics + expanded datasets (33b3f55)
- fix: add benchmarks crate to Dockerfile + update TODO with Loop 1 completion (115176f)
- feat(security): unicode evasion defenses — emoji, upside-down, tags, diacritics, braille (a62855b)
- docs: add implementation TODO list with RALPH loop methodology (b408057)
- fix: code_security regex patterns + R8 formatting (aa9ab98)
- feat(security): configurable threshold system for EnsembleSecurityAnalyzer (R8) (41e219b)
- fix: cargo fmt formatting in benchmarks crate (401c29a)
- feat: add code_security module, benchmark suite, and feature roadmap (b08dccc)
- docs: add protocol exploits survey and benchmarks/tools landscape analysis (0b044c9)
- docs: add multi-agent defense pipeline research analysis (96f8ae4)
- docs: add indirect injection firewalls research analysis (338f3f4)
- docs: add guardrail bypassing research analysis (25499da)
- docs: add InjecGuard research analysis (4f5fddb)
- docs: add defense via tool result parsing research analysis (15ca4a1)
- docs: add design patterns for securing agents research analysis (567cc76)
- feat: add dedicated jailbreak detection with encoding evasion analysis (R10) (03942a1)
- feat: add hallucination detection pipeline for output safety (b28e092)
- feat: add feature-level fusion, output toxicity detection, and streaming output moderation (Phase 2) (41b7f2b)
- feat: add unicode normalisation, secret scanning, and PII checksum validation (583c5c2)
- feat: add unicode normalisation, secret scanning, and PII checksum validation (2969fd7)
- feat: add expanded attack category detection (flattery, urgency, roleplay, impersonation, many-shot, repetition) (9a955a6)
- docs: add security state-of-the-art research report and gap analysis (2a14ca6)
- docs: remove emojis from documentation (bedcdda)
- examples: comprehensive examples overhaul with clean configs and code samples (de5639f)
- docs: comprehensive documentation overhaul with quickstart and integration guides (bd2e42d)
- fix: resolve type mismatches in ClickHouse and PostgreSQL storage (6444e1b)
- fix: replace docker compose --wait with manual health polling in CI (73db68f)
- chore: update pricing.yaml with comprehensive verified model pricing (d6df3aa)
- chore: update pricing.yaml with comprehensive verified model pricing (b9bbcf6)
- fix: add public dir and fix Dockerfile COPY syntax for dashboard (812e478)
- chore: set author to Evangelos Pappas <epappas@evalonlabs.com> across manifests (3ed6ea7)
- docs: add SECURITY.md with vulnerability reporting policy (a45ea50)
- chore: add config.yaml to .gitignore (5899ff1)
- refactor: move proto files to crates/llmtrace-proto (3777d9b)
- refactor: move Node.js bindings from bindings/node to crates/llmtrace-nodejs (f21ebc6)
- refactor: move Python tests into llmtrace-python crate (a68b1c6)
- fix: add C++ toolchain to Docker build and increase compose healthcheck tolerance (8f18593)
- docs: add custom policy setup guide and example configurations (184f3f6)
- fix: commit Cargo.lock and fix CI integration test timeouts (bd70479)
- feat: add per-tenant rate limiting and persistent compliance reports (Loop 41) (85c7f2f)
- ci: add integration tests with Docker Compose and Trivy container scanning (Loop 40) (09395c0)
- feat: harden secrets management and add startup probe (Loop 39) (19f0366)
- feat: add database migration management with versioned schemas (Loop 38) (5658502)
- feat: add Prometheus metrics endpoint with request/security/storage instrumentation (Loop 37) (ad7cf66)
- feat: add graceful shutdown with signal handling and task draining (Loop 36) (516fa86)
- feat: externalize pricing config and add OWASP LLM Top 10 test framework (Loop 35) (97c1e92)
- feat: add multi-channel alerting with Slack and PagerDuty support (Loop 34) (c50f4ca)
- feat: add ML inference monitoring and model warm-up (Loop 33) (96ebf10)
- feat: add ML-based PII detection via NER model (Loop 32) (beb7b92)
- feat: expand PII detection with international patterns, context suppression, and redaction (Loop 31) (d4fb618)
- feat: add real-time streaming security analysis (Loop 30) (718d830)
- feat: add statistical anomaly detection engine (Loop 29) (5746cd4)
- docs: add ADRs and Phase 5-6 loops (AI + MLOps review fixes) (0833f61)
- feat: add Node.js bindings via NAPI-RS (Loop 28) (3a5ae8b)
- feat: add WebAssembly bindings for browser-side security analysis (Loop 27) (c10804a)
- feat: add Kubernetes Helm chart and deployment docs (Loop 26) (e871088)
- ci: install protoc for gRPC proto compilation (ba7c1bb)
- feat: add gRPC ingestion gateway with tonic (Loop 25) (addc90a)
- feat: add compliance reporting for SOC2, GDPR, and HIPAA (Loop 24) (4306187)
- feat(auth): add RBAC & API key authentication (Loop 23) (db944ba)
- ci: add GitHub Actions CI/CD pipeline with lint, test, release, and security audit (7ae9ef0)
- feat(dashboard): scaffold Next.js 14 web dashboard (Loop 21) (33339df)
- feat: add OpenTelemetry OTLP/HTTP ingestion gateway (Loop 20) (f3451be)
- feat(security): add ML-based prompt injection detection with candle (Loop 19) (cd9c408)
- docs: add Phase 4 loops (19-28) — ML detection, OTEL, dashboard, CI/CD, RBAC, compliance, gRPC, K8s, WASM, Node.js (f08846f)
- fix: bump Docker Rust to 1.93 (clickhouse crate needs ≥1.89) (643f3b6)
- feat: add agent tool & skill usage tracing (Loop 18) (10d829c)
- fix: bump Rust to 1.85 for edition2024 support (5d901e9)
- chore: add Dockerfile + scripts/build.sh + scripts/push.sh for GHCR (b0302f6)
- chore: rename to compose.yaml, add .env.example for easy dev setup (7f72af0)
- feat: agent cost caps & budget enforcement (Loop 17) (a052a92)
- feat: add Redis CacheLayer, Production StorageProfile, and Docker Compose (Loop 16) (1d9e297)
- feat(storage): add PostgreSQL MetadataRepository backend (1533659)
- docs: add Phase 3 loops (14-18) to RALPH_LOOPS.md (7686e45)
- feat(storage): add ClickHouse TraceRepository backend (dcf100d)
- feat: add tenant management API with CRUD, audit events, and auto-creation (89fd51b)
- feat: add alert engine with webhook notifications for security findings (eec5b5b)
- feat(cost): add cost estimation engine for LLM API requests (44d6dcc)
- feat(proxy): add LLM provider auto-detection and provider-specific response parsing (c6d5315)
- feat: add REST Query API for traces, spans, and security findings (Loop 9) (f961070)
- docs: add Phase 2 RALPH loops (9-13) — query API, provider detection, cost estimation, alerts, tenant mgmt (cdee306)
- fix(examples): update model to Qwen2.5-7B, add uv inline script metadata (7a1402b)
- feat: add integration tests, examples, README, and MIT license (loop 8) (a228a64)
- feat(python): implement Python bindings with PyO3 and maturin (8645d11)
- feat: add CLI with clap, env var overrides, config validation, and structured logging (9d55a35)
- feat: refactor storage layer with repository pattern (Loop 5.5) (373b6f0)
- fix: extract token usage from non-streaming responses and persist security findings to spans (ed910fe)
- feat: wire streaming SSE accumulator into proxy handler (0541ec3)
- docs: add Loop 5.5 — storage layer repository pattern refactoring (be9a9ed)
- feat: switch proxy from in-memory to SQLite persistent storage (78ccc32)
- feat: implement transparent proxy server (Loop 4) (411eb14)
- feat(security): implement comprehensive regex-based prompt injection detection (31d29a8)
- feat(storage): implement SQLite storage backend with proper schema and query filtering (2ef8608)
- feat: implement Loop 1 - enrich llmtrace-core with complete types, traits, and tests (d32ab94)
- docs: strengthen coding agent quality standards - DRY, KISS, testing, Rust patterns (f774c93)
- feat: scaffold workspace with 6 crates, architecture docs, and RALPH loop plan (d134791)
