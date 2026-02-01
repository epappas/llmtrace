"use client";

import { useEffect, useState } from "react";
import { Plus, Trash2, Users } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { DataTable } from "@/components/data-table";
import type { Tenant } from "@/lib/api";

export default function TenantsPage() {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState("");
  const [newPlan, setNewPlan] = useState("default");

  async function loadTenants() {
    try {
      const res = await fetch("/api/proxy/tenants");
      setTenants(await res.json());
    } catch {
      /* ignore */
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
      await fetch("/api/proxy/tenants", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: newName, plan: newPlan }),
      });
      setNewName("");
      setNewPlan("default");
      setShowCreate(false);
      await loadTenants();
    } catch {
      /* ignore */
    }
  }

  async function handleDelete(id: string) {
    if (!confirm("Delete this tenant?")) return;
    try {
      await fetch(`/api/proxy/tenants/${id}`, { method: "DELETE" });
      await loadTenants();
    } catch {
      /* ignore */
    }
  }

  const columns = [
    {
      header: "Name",
      accessor: (t: Tenant) => <span className="font-medium">{t.name}</span>,
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
      header: "",
      accessor: (t: Tenant) => (
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
      ),
      className: "w-12",
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
