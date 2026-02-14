"use client";

import { useEffect, useState, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { ArrowLeft, Save, Shield, Activity, DollarSign, Settings } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import {
  getTenant,
  updateTenant,
  type Tenant,
  type MonitoringScope,
  type TenantConfig
} from "@/lib/api";

function ConfigContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const tenantId = searchParams.get("id");
  const [tenant, setTenant] = useState<Tenant | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  // Form state
  const [name, setName] = useState("");
  const [plan, setPlan] = useState("");
  const [scope, setScope] = useState<MonitoringScope>("hybrid");
  const [rateLimit, setRateLimit] = useState<string>("");
  const [budget, setBudget] = useState<string>("");

  useEffect(() => {
    async function load() {
      if (!tenantId) {
        setError("No tenant ID provided");
        setLoading(false);
        return;
      }
      try {
        const data = await getTenant(tenantId);
        setTenant(data);
        setName(data.name);
        setPlan(data.plan);
        setScope(data.config.monitoring_scope || "hybrid");
        setRateLimit(data.config.rate_limit_rpm?.toString() || "");
        setBudget(data.config.monthly_budget?.toString() || "");
      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to load tenant");
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [tenantId]);

  async function handleSave() {
    if (!tenantId) return;
    setSaving(true);
    setSuccess(false);
    setError(null);
    try {
      const configUpdate: Partial<TenantConfig> = {
        monitoring_scope: scope,
        rate_limit_rpm: rateLimit ? parseInt(rateLimit, 10) : undefined,
        monthly_budget: budget ? parseFloat(budget) : undefined,
      };

      await updateTenant(tenantId, {
        name,
        plan,
        config: configUpdate
      });
      setSuccess(true);
      setTimeout(() => setSuccess(false), 3000);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to save configuration");
    } finally {
      setSaving(false);
    }
  }

  if (loading) return <div className="p-8 text-center">Loading configuration…</div>;
  if (error && !tenant) return <div className="p-8 text-center text-destructive">{error}</div>;
  if (!tenant) return <div className="p-8 text-center text-destructive">Tenant not found</div>;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" onClick={() => router.back()}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <h1 className="text-3xl font-bold" data-testid="tenant-config-heading">Tenant Configuration</h1>
        </div>
        <Button onClick={handleSave} disabled={saving} className="gap-2">
          <Save className="h-4 w-4" />
          {saving ? "Saving..." : "Save Changes"}
        </Button>
      </div>

      {success && (
        <div className="bg-green-500/10 border border-green-500/20 text-green-600 p-3 rounded-md text-sm">
          Configuration saved successfully
        </div>
      )}

      {error && (
        <div className="bg-destructive/10 border border-destructive/20 text-destructive p-3 rounded-md text-sm">
          {error}
        </div>
      )}

      <div className="grid gap-6 md:grid-cols-2">
        {/* General Settings */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Settings className="h-4 w-4" /> General Settings
            </CardTitle>
            <CardDescription>Basic tenant information and plan</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Tenant Name</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="w-full rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Subscription Plan</label>
              <select
                value={plan}
                onChange={(e) => setPlan(e.target.value)}
                className="w-full rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
              >
                <option value="default">Default</option>
                <option value="free">Free</option>
                <option value="pro">Pro</option>
                <option value="enterprise">Enterprise</option>
              </select>
            </div>
          </CardContent>
        </Card>

        {/* Security & Monitoring */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Shield className="h-4 w-4" /> Security & Monitoring
            </CardTitle>
            <CardDescription>Configure how LLM interactions are observed</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Monitoring Scope</label>
              <select
                name="monitoring_scope"
                value={scope}
                onChange={(e) => setScope(e.target.value as MonitoringScope)}
                className="w-full rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
              >
                <option value="hybrid">Hybrid (Input + Output)</option>
                <option value="input_only">Input Only</option>
                <option value="output_only">Output Only</option>
              </select>
              <p className="text-xs text-muted-foreground">
                Control which parts of the interaction are analyzed for security findings.
              </p>
            </div>
          </CardContent>
        </Card>

        {/* Rate Limiting */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Activity className="h-4 w-4" /> Rate Limiting
            </CardTitle>
            <CardDescription>Prevent abuse by limiting request volume</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Requests Per Minute (RPM)</label>
              <input
                type="number"
                name="rate_limit_rpm"
                placeholder="Unlimited"
                value={rateLimit}
                onChange={(e) => setRateLimit(e.target.value)}
                className="w-full rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
              />
            </div>
          </CardContent>
        </Card>

        {/* Cost Control */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <DollarSign className="h-4 w-4" /> Cost Control
            </CardTitle>
            <CardDescription>Set budget limits for this tenant</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Monthly Budget (USD)</label>
              <input
                type="number"
                name="monthly_budget"
                step="0.01"
                placeholder="Unlimited"
                value={budget}
                onChange={(e) => setBudget(e.target.value)}
                className="w-full rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
              />
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

export default function TenantConfigPage() {
  return (
    <Suspense fallback={<div className="p-8 text-center">Loading configuration…</div>}>
      <ConfigContent />
    </Suspense>
  );
}
