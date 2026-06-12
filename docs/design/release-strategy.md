# Release strategy and self-serve instance updates

Status: PROPOSAL — decision asks in section 6 require sign-off before any build.
Issue: techlab-innov/llmtrace#383 (mirrored as Portal#66). Author: platform
operations, 2026-06-12.

## 1. Current state (verified)

- Versioning: the cargo workspace is at `0.2.1`; the last git tag and GitHub
  Release are `v0.2.0` (2026-04-17). Everything merged since April is live on
  customers' instances but unreleased and unannounced.
- Images: `publish-images.yml` pushes `:sha-<7>`, `:main` and `:latest` on
  every qualifying push to main. There are no version-tagged images. Every
  published image IS uniquely addressable via its `sha-<7>` tag today.
- Known trigger gap: the workflow's path filter does not include
  `config.example.yaml` (the baked proxy config), so config-only changes need
  a manual `workflow_dispatch` to rebuild.
- Provisioning: the Portal pins `ghcr.io/...:latest` at provision time
  (`instances.image_version` exists but is never set, so the `"latest"`
  fallback applies). An instance therefore runs whatever `:latest` happened to
  be at its provision moment, and nothing records what that was.
- Upgrade machinery: the Basilica SDK has create/get/delete/restart/scale —
  NO in-place update. The only rebuild path is recreate, and:
  - Basilica URLs derive from the deployment UUID, so recreate ALWAYS changes
    the customer's proxy and dashboard URLs.
  - Per-deployment sqlite dies with the pod: traces, customer-minted proxy
    API keys, and tenant records/tokens are lost. The portal re-seeds tenant
    identity (stable `tenant_uuid`) and upstream config automatically, and
    re-bakes the same admin key from the vault (dashboard SSO survives), but
    it stores only hashes/metadata for customer API keys — their plaintext
    cannot be restored, only re-minted with NEW values.
  - The proxy ML preload allows up to 1500s of startup, so a recreate can
    mean a multi-minute (worst case ~25 min) provisioning window.

## 2. What the customer asked for (#383)

1. A formal release cadence and release-notes policy that separates new
   features from security and bug fixes (including dependency-driven ones).
2. In-portal "update available" notification per instance.
3. A one-click upgrade button that shows the release notes before applying.
4. No forced rollouts — single-tenant customers control their own timing.

## 3. Proposed release process (product repo)

### 3.1 Versioning and artifacts

- Semver tags `vX.Y.Z` on main; one GitHub Release per tag (canonical record);
  CHANGELOG.md updated in the same PR that cuts the release.
- Extend `publish-images.yml` with a tag trigger: a `v*` tag builds BOTH
  images unconditionally (no path filter on release builds — closes the
  config-only gap for releases) and pushes `:X.Y.Z`, `:X.Y` and `:latest`.
- First action once approved: cut `v0.3.0` covering everything since v0.2.0
  (the backlog includes security-relevant proxy changes — e.g. the /v1
  de-dup, tenant-record upstream delivery — that deserve notes).

### 3.2 Release-notes template

Required sections, in this order, every release:

```
## Security fixes        <- CVEs / dependency bumps / hardening, each with impact
## Bug fixes
## Features
## Operational notes     <- migrations, env/config changes, expected downtime
Upgrade urgency: security | recommended | optional
```

The urgency line is machine-readable on purpose — the portal surfaces it on
the update banner (a `security` release renders differently from `optional`).

### 3.3 Cadence

- Minor releases: monthly floor (more often when customer-visible work lands).
- Patch releases: as needed.
- Security releases: out-of-band, as soon as fixed; notes may be terse at
  publish time and amended after customers upgrade.

## 4. Proposed portal work (Portal repo)

### 4.1 Version pinning at provision (low risk, build first)

- New provisions resolve the latest release version and pin the concrete
  image tag (`:X.Y.Z`), recording it in `instances.image_version`. No more
  "whatever :latest was". Existing instances get `image_version` backfilled
  from their deployment's image reference where Basilica reports it, else
  marked `unknown (pre-versioning)`.

### 4.2 Update-available detection

- A small cached check (kv table, refreshed by the existing cron, ~hourly):
  latest GitHub Release tag + urgency vs each instance's `image_version`.
- Banner on the portal dashboard and instance pages linking to the release
  notes. This ships WITHOUT the button and is honest on its own: customers
  learn that updates exist and what is in them.

### 4.3 The upgrade button — gated on the URL-stability decision

Upgrade-by-recreate today means: new URLs, traces wiped, API keys re-minted
with new values, multi-minute window. Three paths:

- **Option A — ship now, brutally honest.** The confirm modal enumerates
  exactly what changes (URL churn, trace loss, key re-mint, downtime
  estimate); after upgrade the portal shows the new URLs and new keys
  (re-minted automatically, displayed once). Cheapest; worst experience;
  every client integration breaks on every upgrade until re-pointed.
- **Option B — portal-owned stable hostnames first (recommended).** One
  subdomain per instance (e.g. `{instance}.llmtrace.io`) on a portal-managed
  edge (Cloudflare DNS/Worker) pointing at the current Basilica URL. Upgrade
  becomes blue/green: create the new deployment, wait until ready (absorbs
  the ML-preload window with zero downtime), re-seed tenants/config, flip the
  alias, delete the old deployment. The customer URL never changes — this
  also retires URL churn for resizes and recovery recreates, and it is a
  prerequisite the trace-durability roadmap shares. Residual loss: traces and
  minted keys still die with the sqlite volume (see 4.4).
- **Option C — Basilica feature ask.** In-place image update, stable URLs, or
  persistent volumes. Zero portal work if delivered; timeline not ours.
  Worth requesting in parallel regardless (it is also the blocker for trace
  durability), but not a plan on its own.

### 4.4 Customer API keys across upgrades (decision needed)

Even with stable URLs, recreate loses proxy-side key material. Choices:

- **Re-mint honestly (default):** the upgrade flow re-mints every active
  portal-managed key in the new proxy and shows the new values once; release
  notes say "rotate your clients". Zero product work; breaks client configs
  on every upgrade.
- **Proxy key export/import (product feature):** an admin-API pair to export
  encrypted key records and import them into a fresh deployment, letting the
  portal restore keys with IDENTICAL plaintext. Touches credential-handling
  code — needs its own security review before being scheduled.
- **External durable storage:** solves keys AND traces; blocked on Basilica
  persistent volumes / external DB (tracked separately).

## 5. Sequencing

1. Now (after sign-off): 3.1–3.3 — cut v0.3.0 with backfilled notes; tag-
   triggered image builds.
2. Portal: 4.1 version pinning, then 4.2 update banner. No button yet.
3. ADR with the operator: pick A/B/C (4.3) and the key story (4.4).
4. Build the button on whatever 3 decides.

## 6. Decision asks

- D1: approve the cadence + template (3.2/3.3) and cutting v0.3.0.
- D2: approve version-pinned provisioning replacing `:latest` (4.1).
- D3: choose the upgrade path: A (honest churn), B (stable hostnames,
  recommended), or C-first (wait on Basilica).
- D4: choose the key-continuity story: honest re-mint, or schedule the proxy
  key export/import feature (with security review).
