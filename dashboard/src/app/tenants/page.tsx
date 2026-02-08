"use client";

import { useEffect, useState } from "react";
import { Plus, Trash2, Users, Key, Copy, Check, AlertTriangle } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { DataTable } from "@/components/data-table";
import {
  type Tenant,
  listTenants,
  createTenant,
  deleteTenant,
  createApiKey,
  type ApiKey,
} from "@/lib/api";

export default function TenantsPage() {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState("");
  const [newPlan, setNewPlan] = useState("default");
  const [generatedKey, setGeneratedKey] = useState<ApiKey | null>(null);
  const [copied, setCopied] = useState(false);

  async function loadTenants() {
    setLoading(true);
    setError(null);
    try {
      console.log("[Tenants] Loading tenants from proxy...");
      const data = await listTenants();
      console.log("[Tenants] Data received:", data);
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
      console.log(`[Tenants] Creating tenant: ${newName}`);
      await createTenant({ name: newName, plan: newPlan });
      console.log("[Tenants] Created successfully");
      setNewName("");
      setNewPlan("default");
      setShowCreate(false);
      await loadTenants();
    } catch (e) {
      console.error("[Tenants] Create failed:", e);
      setError(e instanceof Error ? e.message : "Failed to create tenant");
    }
  }

  async function handleDelete(id: string) {
    if (!confirm("Delete this tenant?")) return;
    try {
      console.log(`[Tenants] Deleting tenant: ${id}`);
      await deleteTenant(id);
      console.log(`[Tenants] Delete successful, reloading list`);
      await loadTenants();
    } catch (e) {
      console.error("[Tenants] Delete failed:", e);
      alert("Failed to delete tenant. Check console for details.");
    }
  }

  async function handleGenerateToken(tenantId: string, tenantName: string) {
    try {
      const key = await createApiKey(tenantId, `Key for ${tenantName}`);
      setGeneratedKey(key);
    } catch (e) {
      console.error("[Tenants] Token generation failed:", e);
      alert("Failed to generate token.");
    }
  }

  const copyToClipboard = (text: string) => {
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text);
    } else {
      // Fallback for non-secure contexts
      const textArea = document.createElement("textarea");
      textArea.value = text;
      textArea.style.position = "fixed";
      textArea.style.left = "-9999px";
      textArea.style.top = "0";
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();
      try {
        document.execCommand('copy');
      } catch (err) {
        console.error('Fallback copy failed', err);
      }
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
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={(e) => {
              e.stopPropagation();
              handleGenerateToken(t.id, t.name);
            }}
          >
            <Key className="mr-2 h-3 w-3" /> Token
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
      className: "w-32",
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold">Tenants</h1>
        <Button onClick={() => setShowCreate(!showCreate)}>
          <Plus className="mr-2 h-4 w-4" /> New Tenant
        </Button>
      </div>

      {generatedKey && (
        <Card className="border-primary bg-primary/5">
          <CardHeader>
            <CardTitle className="text-base text-primary flex items-center gap-2">
              <Key className="h-4 w-4" /> Token Generated
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
