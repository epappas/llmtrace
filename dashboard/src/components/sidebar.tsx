"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import {
  LayoutDashboard,
  FileSearch,
  Shield,
  DollarSign,
  Users,
  Settings,
  User,
  FileCheck,
  BookOpen,
  Gauge,
  ScrollText,
  Code,
  MessageSquare,
  LogOut,
} from "lucide-react";
import { cn } from "@/lib/utils";
import {
  listTenants,
  setStoredTenant,
  type Tenant,
  DEFAULT_TENANT_ID,
  ALL_TENANTS_SCOPE,
  STORED_TENANT_KEY,
  TENANTS_CHANGED_EVENT,
} from "@/lib/api";

const navItems = [
  { href: "/", label: "Overview", icon: LayoutDashboard },
  { href: "/traces", label: "Traces", icon: FileSearch },
  { href: "/security", label: "Security", icon: Shield },
  { href: "/audit", label: "Audit", icon: ScrollText },
  { href: "/playground", label: "Playground", icon: MessageSquare },
  { href: "/costs", label: "Costs", icon: DollarSign },
  { href: "/tenants", label: "Tenants", icon: Users },
  { href: "/compliance", label: "Compliance", icon: FileCheck },
  { href: "/status", label: "Status", icon: Gauge },
  { href: "/api-docs", label: "API Docs", icon: Code },
  { href: "/guide", label: "Guide", icon: BookOpen },
  { href: "/settings", label: "Settings", icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [selectedTenant, setSelectedTenant] = useState<string>(DEFAULT_TENANT_ID);

  const loadTenants = useCallback(async () => {
    try {
      const data = await listTenants();
      setTenants(data);
      const stored = localStorage.getItem(STORED_TENANT_KEY);

      if (
        stored &&
        (stored === ALL_TENANTS_SCOPE ||
          stored === DEFAULT_TENANT_ID ||
          data.some((t) => t.id === stored))
      ) {
        setSelectedTenant(stored);
      } else if (data.length > 0) {
        // Either nothing is stored, or the stored tenant no longer exists
        // (e.g. it was just deleted). Fall back to the first tenant AND
        // reconcile localStorage so later API calls don't keep sending the
        // stale/dead tenant id in X-LLMTrace-Tenant-ID (issue 7).
        setSelectedTenant(data[0].id);
        setStoredTenant(data[0].id);
      } else {
        // No tenants exist in the DB — fall back to the nil tenant and clear
        // any stale stored id so reads don't scope to a non-existent tenant.
        setSelectedTenant(DEFAULT_TENANT_ID);
        setStoredTenant(DEFAULT_TENANT_ID);
      }
    } catch (e) {
      console.error("Failed to load tenants in sidebar", e);
      setSelectedTenant(DEFAULT_TENANT_ID);
    }
  }, []);

  useEffect(() => {
    void loadTenants();
    // Re-run when the tenant registry changes (e.g. a tenant was created on
    // the /tenants page) so the selector picks up new tenants without a full
    // page reload. See issue 7.
    const onChanged = () => void loadTenants();
    window.addEventListener(TENANTS_CHANGED_EVENT, onChanged);
    return () => window.removeEventListener(TENANTS_CHANGED_EVENT, onChanged);
  }, [loadTenants]);

  const handleTenantChange = (id: string) => {
    setSelectedTenant(id);
    setStoredTenant(id);
    // Refresh the page so every page re-resolves its tenant/scope from the
    // new selection (read pages call findActiveTenant on mount).
    window.location.reload();
  };

  const handleSignOut = async () => {
    try {
      await fetch("/api/auth/logout", { method: "POST" });
    } catch (e) {
      console.error("Sign out failed:", e);
    } finally {
      window.location.assign("/login");
    }
  };

  return (
    <aside className="flex h-screen w-64 flex-col border-r bg-card">
      <div className="flex h-14 items-center border-b px-4">
        <Link href="/" className="flex items-center gap-2 font-bold text-lg">
          <Shield className="h-6 w-6 text-primary" />
          <span>LLMTrace</span>
        </Link>
      </div>

      <div className="p-4 border-b">
        <label className="text-[10px] uppercase font-bold text-muted-foreground mb-2 block">
          Current Tenant
        </label>
        <div className="relative">
          <select
            value={selectedTenant}
            onChange={(e) => handleTenantChange(e.target.value)}
            data-testid="tenant-selector"
            className="w-full bg-background border rounded-md px-3 py-2 text-sm appearance-none cursor-pointer focus:outline-none focus:ring-2 focus:ring-primary"
          >
            {/* Admin-only aggregate view: reads scope to every tenant. */}
            <option value={ALL_TENANTS_SCOPE}>All tenants</option>
            {/* Always include the Default/Nil tenant if it's the only one or currently selected */}
            {(tenants.length === 0 || selectedTenant === DEFAULT_TENANT_ID) && (
              <option value={DEFAULT_TENANT_ID}>Default Tenant</option>
            )}
            {tenants.map((t) => (
              <option key={t.id} value={t.id}>
                {t.name}
              </option>
            ))}
          </select>
          <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2 text-muted-foreground">
            <User className="h-3 w-3" />
          </div>
        </div>
      </div>

      <nav className="flex-1 space-y-1 p-3">
        {navItems.map((item) => {
          const active =
            item.href === "/"
              ? pathname === "/"
              : pathname.startsWith(item.href);
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                active
                  ? "bg-primary text-primary-foreground"
                  : "text-muted-foreground hover:bg-accent hover:text-accent-foreground",
              )}
            >
              <item.icon className="h-4 w-4" />
              {item.label}
            </Link>
          );
        })}
      </nav>
      <div className="border-t p-3 space-y-2">
        <button
          type="button"
          onClick={handleSignOut}
          data-testid="sign-out-button"
          className="flex w-full items-center gap-2 rounded-md px-3 py-2 text-sm font-medium text-muted-foreground transition-colors hover:bg-accent hover:text-accent-foreground"
        >
          <LogOut className="h-4 w-4" />
          Sign out
        </button>
        <div className="px-3 text-xs text-muted-foreground">LLMTrace Dashboard v0.1.0</div>
      </div>
    </aside>
  );
}
