# LLMTrace Dashboard — Feature & Fix Audit (2026-02-08)

This document summarizes the architectural improvements, feature additions, and bug fixes applied to the LLMTrace Dashboard.

## 🚀 New Features

### 1. Multi-Tenant Observability
- **Tenant Selector:** Added a persistent dropdown in the sidebar to manually switch between different tenants.
- **Freshness-Aware Selection:** Logic added to automatically identify and switch to the tenant with the most recent LLM activity on startup.
- **Unified Global Stats:** Added a "Global Transactions" counter to the Overview, aggregating data across all tenants in the cluster.

### 2. Enhanced Trace Visibility
- **Prompt & Response Mapping:** Fixed a data-binding bug where conversation content was not appearing due to field name mismatches (`prompt` vs `prompt_text`).
- **Trace Detail Context:** Updated the detail view to be tenant-aware, ensuring 100% visibility of traces even in multi-tenant environments.
- **Action Management:** Added a "Delete Trace" option with direct ClickHouse integration.

### 3. Advanced Filtering & Sorting
- **Smart Filters:** Added real-time filtering for **Trace ID** and **Date** in the Traces list.
- **Dynamic Sorting:** Enhanced the `DataTable` component to support column-based sorting (Latency, Cost, Tokens, Date).

### 4. Token & Security Management
- **One-Time Token Generation:** Added a "Generate Token" workflow in the Tenants tab.
- **Secure Copy:** Implemented a clipboard fallback for non-secure (HTTP) contexts to ensure tokens can be copied easily.
- **PostgreSQL Cascading Deletes:** Updated the database schema (`audit_events`) to allow clean tenant deletion without foreign-key conflicts.

### 5. Platform Modernization
- **Next.js 15 Upgrade:** Upgraded the entire dashboard stack to Next.js 15.1.2 and React 19.
- **Breaking Change Fixes:** Refactored dynamic routes and page components to handle the new Promise-based `params` and `searchParams` API.

---

## 🛠 Bug Fixes & Optimizations

- **502 Bad Gateway:** Fixed by correcting internal Docker DNS resolution and bypassing faulty server-side proxy routes.
- **404 Costs Error:** Resolved by enabling `cost_caps` in the proxy configuration.
- **Health Check Status:** Updated dashboard to correctly recognize the `"healthy"` status returned by the Rust backend.
- **Junk Tenant Prevention:** Patched the Rust proxy to stop auto-creating tenants for unauthenticated scanner traffic.
- **Real-Time Polling:** Added 30-second auto-refresh to all major dashboard views.

---

## 🧪 Testing Suite (Playwright)

A new E2E test suite has been added in `dashboard/e2e/dashboard.spec.ts` covering:
- **Tenant Lifecycle:** Create -> Token Gen -> Delete.
- **Data Integrity:** Verifying Stats cards and Chart rendering.
- **Detail Accuracy:** Ensuring Prompts and Responses load correctly.
- **Persistence:** Verifying the Sidebar remembers your selected tenant.

### Running Tests
```bash
cd dashboard
npm install
npx playwright install --with-deps
npm run test:e2e
```
