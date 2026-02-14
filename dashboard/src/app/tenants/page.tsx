"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Plus, Trash2, Users, Key, Copy, Check, AlertTriangle, Settings, Shield, Activity, DollarSign, Save, X } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { DataTable } from "@/components/data-table";
import {
  type Tenant,
  type MonitoringScope,
  type TenantConfig,
  listTenants,
  getTenant,
  createTenant,
  deleteTenant,
  resetTenantToken,
  createApiKey,
  listApiKeys,
  revokeApiKey,
  updateTenant,
  type ApiKey,
} from "@/lib/api";

export default function TenantsPage() {
  const router = useRouter();
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState("");
  const [newPlan, setNewPlan] = useState("default");
  const [newKeyRole, setNewKeyRole] = useState<"admin" | "operator" | "viewer">("operator");
  const [generatedKey, setGeneratedKey] = useState<ApiKey | null>(null);
  const [activeTenantKeys, setActiveTenantKeys] = useState<{tenantId: string, tenantName: string, keys: ApiKey[], apiToken?: string} | null>(null);
  const [copied, setCopied] = useState(false);

  // Configuration Modal State
  const [editingConfig, setEditingConfig] = useState<Tenant | null>(null);
  const [configName, setConfigName] = useState("");
  const [configPlan, setConfigPlan] = useState("");
  const [configScope, setConfigScope] = useState<MonitoringScope>("hybrid");
  const [configRateLimit, setConfigRateLimit] = useState("");
  const [configBudget, setConfigBudget] = useState("");
  const [configSaving, setConfigSaving] = useState(false);
  const [configSuccess, setConfigSuccess] = useState(false);

  async function loadTenants() {
    setLoading(true);
    setError(null);
    try {
      console.log("[Tenants] Loading tenants from proxy...");
      const data = await listTenants();
      setTenants(data || []);
    } catch (e) {
      console.error("[Tenants] Load failed:", e);
      setError(e instanceof Error ? e.message : "Failed to connect to proxy API");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadTenants();
  }, []);

  async function handleCreate() {
    if (!newName.trim()) return;
    try {
      const res = await createTenant({ name: newName, plan: newPlan });
      if (res.api_key) {
        setGeneratedKey({
          id: "new",
          name: "Default Key",
          key: res.api_key,
          key_prefix: res.api_key.slice(0, 12),
          role: "admin",
          created_at: new Date().toISOString(),
          revoked_at: null,
          tenant_id: res.id
        });
      }
      setNewName("");
      setNewPlan("default");
      setShowCreate(false);
      await loadTenants();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create tenant");
    }
  }

  async function handleDelete(id: string) {
    if (!confirm("Delete this tenant?")) return;
    try {
      await deleteTenant(id);
      await new Promise(resolve => setTimeout(resolve, 500));
      window.location.reload();
    } catch (e) {
      alert("Failed to delete tenant");
    }
  }

  async function handleManageToken(tenantId: string, tenantName: string) {
    try {
      const keys = await listApiKeys(tenantId);
      const tenant = await getTenant(tenantId);
      setActiveTenantKeys({ 
        tenantId, 
        tenantName, 
        keys: keys.filter(k => !k.revoked_at),
        apiToken: tenant.api_token 
      });
      setGeneratedKey(null);
    } catch (e) {
      alert("Failed to load existing tokens.");
    }
  }

  async function handleResetToken(tenantId: string) {
    if (!confirm("Regenerate the proxy token?")) return;
    try {
      const res = await resetTenantToken(tenantId);
      if (activeTenantKeys?.tenantId === tenantId) {
        setActiveTenantKeys({ ...activeTenantKeys, apiToken: res.api_token });
      }
    } catch (e) {
      alert("Failed to reset token.");
    }
  }

  async function handleGenerateToken(tenantId: string, tenantName: string, role: "admin" | "operator" | "viewer") {
    try {
      const key = await createApiKey(tenantId, `Key for ${tenantName}`, role);
      setGeneratedKey(key);
      if (activeTenantKeys?.tenantId === tenantId) {
        const keys = await listApiKeys(tenantId);
        setActiveTenantKeys({ ...activeTenantKeys, keys });
      }
    } catch (e) {
      alert("Failed to generate token.");
    }
  }

  async function handleRevokeKey(keyId: string, tenantId: string) {
    if (!confirm("Revoke this token?")) return;
    try {
      await revokeApiKey(keyId, tenantId);
      const keys = await listApiKeys(tenantId);
      setActiveTenantKeys(prev => prev ? { ...prev, keys } : null);
    } catch (e) {
      alert("Failed to revoke token.");
    }
  }

  // Config Modal Logic
  async function openConfig(tenant: Tenant) {
    setEditingConfig(tenant);
    setConfigName(tenant.name);
    setConfigPlan(tenant.plan);
    setConfigScope(tenant.config.monitoring_scope || "hybrid");
    setConfigRateLimit(tenant.config.rate_limit_rpm?.toString() || "");
    setConfigBudget(tenant.config.monthly_budget?.toString() || "");
    setConfigSuccess(false);
  }

  async function handleSaveConfig() {
    if (!editingConfig) return;
    setConfigSaving(true);
    try {
      const update: Partial<TenantConfig> = {
        monitoring_scope: configScope,
        rate_limit_rpm: configRateLimit ? parseInt(configRateLimit, 10) : undefined,
        monthly_budget: configBudget ? parseFloat(configBudget) : undefined,
      };
      await updateTenant(editingConfig.id, {
        name: configName,
        plan: configPlan,
        config: update
      });
      setConfigSuccess(true);
      setTimeout(() => {
        setConfigSuccess(false);
        setEditingConfig(null);
        loadTenants();
      }, 1500);
    } catch (e) {
      alert("Failed to save configuration");
    } finally {
      setConfigSaving(false);
    }
  }

  const copyToClipboard = (text: string) => {
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text);
    } else {
      const textArea = document.createElement("textarea");
      textArea.value = text;
      textArea.style.position = "fixed";
      textArea.style.left = "-9999px";
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();
      document.execCommand('copy');
      document.body.removeChild(textArea);
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const columns = [
    {
      header: "Name",
      accessor: (t: Tenant) => <span className="font-medium" data-testid={`tenant-name-${t.name}`}>{t.name}</span>,
    },
    {
      header: "ID",
      accessor: (t: Tenant) => (
        <span className="font-mono text-xs text-muted-foreground">
          {t.id.slice(0, 8)}…
        </span>
      ),
    },
    {
      header: "Plan",
      accessor: (t: Tenant) => <Badge variant="secondary">{t.plan}</Badge>,
    },
    {
      header: "Created",
      accessor: (t: Tenant) => new Date(t.created_at).toLocaleDateString(),
    },
    {
      header: "Actions",
      accessor: (t: Tenant) => (
        <div className="flex items-center gap-2 relative z-10">
          <Button
            variant="outline"
            size="sm"
            onClick={(e) => {
              e.stopPropagation();
              handleManageToken(t.id, t.name);
            }}
            data-testid="manage-token-button"
          >
            <Key className="mr-2 h-3 w-3" /> Token
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={(e) => {
              e.stopPropagation();
              openConfig(t);
            }}
            data-testid="manage-config-button"
          >
            <Settings className="mr-2 h-3 w-3" /> Config
          </Button>
          <Button
            variant="ghost"
            size="icon"
            onClick={(e) => {
              e.stopPropagation();
              handleDelete(t.id);
            }}
          >
            <Trash2 className="h-4 w-4 text-destructive" />
          </Button>
        </div>
      ),
      className: "w-48",
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold">Tenants</h1>
        <div className="flex gap-2">
          <Button variant="outline" onClick={loadTenants}>Refresh</Button>
          <Button onClick={() => setShowCreate(!showCreate)}>
            <Plus className="mr-2 h-4 w-4" /> New Tenant
          </Button>
        </div>
      </div>

      {editingConfig && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <Card className="w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <CardHeader className="flex flex-row items-center justify-between border-b pb-4">
              <div>
                <CardTitle data-testid="tenant-config-heading">Tenant Configuration</CardTitle>
                <CardDescription>Manage settings for {editingConfig.name}</CardDescription>
              </div>
              <Button variant="ghost" size="icon" onClick={() => setEditingConfig(null)}>
                <X className="h-4 w-4" />
              </Button>
            </CardHeader>
            <CardContent className="space-y-6 pt-6">
              {configSuccess && (
                <div className="bg-green-500/10 border border-green-500/20 text-green-600 p-3 rounded-md text-sm">
                  Configuration saved successfully
                </div>
              )}
              
              <div className="grid gap-6 md:grid-cols-2">
                <div className="space-y-4">
                  <div className="space-y-2">
                    <label className="text-sm font-medium flex items-center gap-2">
                      <Settings className="h-3 w-3" /> Tenant Name
                    </label>
                    <input
                      type="text"
                      value={configName}
                      onChange={(e) => setConfigName(e.target.value)}
                      className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium flex items-center gap-2">
                      <Shield className="h-3 w-3" /> Monitoring Scope
                    </label>
                    <select
                      name="monitoring_scope"
                      value={configScope}
                      onChange={(e) => setConfigScope(e.target.value as any)}
                      className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                    >
                      <option value="hybrid">Hybrid (Input + Output)</option>
                      <option value="input_only">Input Only</option>
                      <option value="output_only">Output Only</option>
                    </select>
                  </div>
                </div>
                
                <div className="space-y-4">
                  <div className="space-y-2">
                    <label className="text-sm font-medium flex items-center gap-2">
                      <Activity className="h-3 w-3" /> Rate Limit (RPM)
                    </label>
                    <input
                      type="number"
                      name="rate_limit_rpm"
                      placeholder="Unlimited"
                      value={configRateLimit}
                      onChange={(e) => setConfigRateLimit(e.target.value)}
                      className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium flex items-center gap-2">
                      <DollarSign className="h-3 w-3" /> Monthly Budget (USD)
                    </label>
                    <input
                      type="number"
                      name="monthly_budget"
                      step="0.01"
                      placeholder="Unlimited"
                      value={configBudget}
                      onChange={(e) => setConfigBudget(e.target.value)}
                      className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                    />
                  </div>
                </div>
              </div>

              <div className="flex justify-end gap-2 border-t pt-4">
                <Button variant="outline" onClick={() => setEditingConfig(null)}>Cancel</Button>
                <Button onClick={handleSaveConfig} disabled={configSaving}>
                  <Save className="mr-2 h-4 w-4" />
                  {configSaving ? "Saving..." : "Save Changes"}
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {activeTenantKeys && (
        <Card className="border-primary bg-primary/5">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-base text-primary flex items-center gap-2" data-testid="manage-tokens-title">
              <Key className="h-4 w-4" /> Manage Tokens: {activeTenantKeys.tenantName}
            </CardTitle>
            <Button variant="ghost" size="sm" onClick={() => setActiveTenantKeys(null)}>Close</Button>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2 border-b pb-4 mb-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold flex items-center gap-2">
                  <Key className="h-3 w-3" /> Proxy Token
                </h3>
                <Button 
                  variant="outline" 
                  size="sm" 
                  className="h-7 text-xs"
                  onClick={() => handleResetToken(activeTenantKeys.tenantId)}
                >
                  Reset
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">
                Use this token in your client headers as <code>X-LLMTrace-Token</code>.
              </p>
              {activeTenantKeys.apiToken ? (
                <div className="flex items-center gap-2 rounded-md border bg-background p-2">
                  <code className="flex-1 font-mono text-xs break-all">
                    {activeTenantKeys.apiToken}
                  </code>
                  <Button
                    size="icon"
                    variant="ghost"
                    className="h-8 w-8"
                    onClick={() => copyToClipboard(activeTenantKeys.apiToken ?? "")}
                  >
                    {copied ? <Check className="h-4 w-4 text-green-500" /> : <Copy className="h-4 w-4" />}
                  </Button>
                </div>
              ) : (
                <div className="text-sm text-yellow-600 bg-yellow-500/10 p-2 rounded-md border border-yellow-500/20 flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4" />
                  No proxy token set. Click Reset to generate one.
                </div>
              )}
            </div>

            <h3 className="text-sm font-semibold">API Keys (Dashboard Auth)</h3>
            <div className="space-y-3">
              {activeTenantKeys.keys.map(key => (
                <div key={key.id} className="flex items-center justify-between rounded-md border bg-background p-3">
                  <div className="space-y-1">
                    <p className="text-sm font-medium">{key.name}</p>
                    <p className="text-xs font-mono text-muted-foreground">Prefix: {key.key_prefix}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline">{key.role}</Badge>
                    <Button 
                      variant="ghost" 
                      size="icon" 
                      onClick={() => handleRevokeKey(key.id, activeTenantKeys.tenantId)}
                    >
                      <Trash2 className="h-4 w-4 text-destructive" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
            
            <div className="pt-2 flex items-center gap-2">
              <select
                name="role"
                value={newKeyRole}
                onChange={(e) => setNewKeyRole(e.target.value as any)}
                className="rounded-md border bg-background px-3 py-1.5 text-sm"
              >
                <option value="admin">Admin</option>
                <option value="operator">Operator</option>
                <option value="viewer">Viewer</option>
              </select>
              <Button size="sm" onClick={() => handleGenerateToken(activeTenantKeys.tenantId, activeTenantKeys.tenantName, newKeyRole)} data-testid="generate-token-button">
                <Plus className="mr-2 h-3 w-3" /> Generate New Token
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {generatedKey && (
        <Card className="border-green-600 bg-green-500/5">
          <CardHeader>
            <CardTitle className="text-base text-green-600 flex items-center gap-2" data-testid="new-token-title">
              <Check className="h-4 w-4" /> New Token Generated
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Copy this token now. You will <strong>not</strong> be able to see it again!
            </p>
            <div className="flex items-center gap-2 rounded-md border bg-background p-2">
              <code className="flex-1 font-mono text-xs break-all">
                {generatedKey.key}
              </code>
              <Button
                size="icon"
                variant="ghost"
                onClick={() => copyToClipboard(generatedKey.key ?? "")}
              >
                {copied ? <Check className="h-4 w-4 text-green-500" /> : <Copy className="h-4 w-4" />}
              </Button>
            </div>
            <Button variant="outline" size="sm" onClick={() => setGeneratedKey(null)}>
              Dismiss
            </Button>
          </CardContent>
        </Card>
      )}

      {showCreate && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Create Tenant</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex gap-4">
              <input
                type="text"
                placeholder="Tenant name"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                className="flex-1 rounded-md border bg-background px-3 py-2 text-sm"
              />
              <select
                value={newPlan}
                onChange={(e) => setNewPlan(e.target.value)}
                className="rounded-md border bg-background px-3 py-2 text-sm"
              >
                <option value="default">Default</option>
                <option value="free">Free</option>
                <option value="pro">Pro</option>
                <option value="enterprise">Enterprise</option>
              </select>
              <Button onClick={handleCreate}>Create</Button>
            </div>
          </CardContent>
        </Card>
      )}

      {error && (
        <Card className="border-destructive bg-destructive/5">
          <CardContent className="py-4 flex items-center gap-3 text-destructive">
            <AlertTriangle className="h-5 w-5" />
            <div className="text-sm">
              <p className="font-bold">Error loading tenants</p>
              <p className="text-xs">{error}</p>
            </div>
            <Button variant="outline" size="sm" className="ml-auto" onClick={loadTenants}>
              Retry
            </Button>
          </CardContent>
        </Card>
      )}

      {loading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : (
        <>
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Users className="h-4 w-4" />
            {tenants.length} tenant{tenants.length !== 1 ? "s" : ""}
          </div>
          <DataTable
            columns={columns}
            data={tenants}
            emptyMessage="No tenants yet. Create one to get started."
          />
        </>
      )}
    </div>
  );
}
