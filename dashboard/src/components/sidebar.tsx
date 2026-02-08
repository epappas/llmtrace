"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import {
  LayoutDashboard,
  FileSearch,
  Shield,
  DollarSign,
  Users,
  Settings,
  User,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { listTenants, setStoredTenant, type Tenant } from "@/lib/api";

const navItems = [
  { href: "/", label: "Overview", icon: LayoutDashboard },
  { href: "/traces", label: "Traces", icon: FileSearch },
  { href: "/security", label: "Security", icon: Shield },
  { href: "/costs", label: "Costs", icon: DollarSign },
  { href: "/tenants", label: "Tenants", icon: Users },
  { href: "/settings", label: "Settings", icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [selectedTenant, setSelectedTenant] = useState<string>("");

  useEffect(() => {
    async function load() {
      try {
        const data = await listTenants();
        setTenants(data);
        
        const stored = localStorage.getItem("llmtrace_tenant_id");
        if (stored && data.some(t => t.id === stored)) {
          setSelectedTenant(stored);
        } else if (data.length > 0) {
          // Default to first tenant if none stored or stored is invalid
          setSelectedTenant(data[0].id);
          setStoredTenant(data[0].id);
        } else {
          setSelectedTenant("");
          setStoredTenant(undefined);
        }
      } catch (e) {
        console.error("Failed to load tenants in sidebar", e);
      }
    }
    load();
  }, []);

  const handleTenantChange = (id: string) => {
    setSelectedTenant(id);
    setStoredTenant(id);
    // Reload the page to refresh all data with the new tenant context
    window.location.reload();
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
            className="w-full bg-background border rounded-md px-3 py-2 text-sm appearance-none cursor-pointer"
          >
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
      <div className="border-t p-4 text-xs text-muted-foreground">
        LLMTrace Dashboard v0.1.0
      </div>
    </aside>
  );
}
