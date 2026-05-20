"use client";

import { useEffect, useMemo, useState } from "react";
import { ScrollText, RefreshCw, AlertTriangle, ChevronDown, ChevronRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { DataTable } from "@/components/data-table";
import {
  findActiveTenant,
  listAuditEvents,
  type AuditEvent,
  type ListAuditEventsParams,
} from "@/lib/api";

const PAGE_SIZE = 100;

/** Collapsible JSON viewer for the per-row `data` payload. */
function DataCell({ value }: { value: unknown }) {
  const [open, setOpen] = useState(false);
  const json = useMemo(() => {
    try {
      return JSON.stringify(value, null, 2);
    } catch {
      return String(value);
    }
  }, [value]);

  if (value === null || value === undefined || json === "{}" || json === "null") {
    return <span className="text-xs text-muted-foreground">—</span>;
  }

  return (
    <div className="max-w-xl">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-1 text-xs font-medium text-muted-foreground hover:text-foreground"
        data-testid="audit-data-toggle"
      >
        {open ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
        {open ? "Hide" : "Show"} payload
      </button>
      {open && (
        <pre
          data-testid="audit-data-payload"
          className="mt-2 max-h-60 overflow-auto rounded-md border bg-muted/30 p-2 text-[11px] leading-relaxed"
        >
          {json}
        </pre>
      )}
    </div>
  );
}

export default function AuditPage() {
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tenantId, setTenantId] = useState<string | undefined>(undefined);
  const [filter, setFilter] = useState("");
  const [offset, setOffset] = useState(0);

  async function load(currentTenant: string | undefined, params: ListAuditEventsParams) {
    setLoading(true);
    setError(null);
    try {
      const data = await listAuditEvents(params, currentTenant);
      setEvents(data);
    } catch (e) {
      setEvents(null);
      setError(e instanceof Error ? e.message : "Failed to load audit events");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const t = await findActiveTenant();
      if (cancelled) return;
      setTenantId(t);
      await load(t, { limit: PAGE_SIZE, offset: 0 });
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const handleFilterApply = () => {
    setOffset(0);
    load(tenantId, {
      limit: PAGE_SIZE,
      offset: 0,
      event_type: filter.trim() || undefined,
    });
  };

  const handlePage = (direction: "prev" | "next") => {
    const nextOffset =
      direction === "prev" ? Math.max(0, offset - PAGE_SIZE) : offset + PAGE_SIZE;
    setOffset(nextOffset);
    load(tenantId, {
      limit: PAGE_SIZE,
      offset: nextOffset,
      event_type: filter.trim() || undefined,
    });
  };

  const columns = [
    {
      header: "Timestamp",
      accessor: (e: AuditEvent) => (
        <span className="font-mono text-xs">
          {new Date(e.timestamp).toLocaleString()}
        </span>
      ),
    },
    {
      header: "Event type",
      accessor: (e: AuditEvent) => (
        <Badge variant="secondary" className="font-mono text-[11px]">
          {e.event_type}
        </Badge>
      ),
    },
    {
      header: "Actor",
      accessor: (e: AuditEvent) => (
        <span className="text-xs text-muted-foreground">{e.actor || "—"}</span>
      ),
    },
    {
      header: "Resource",
      accessor: (e: AuditEvent) => (
        <span className="font-mono text-[11px] break-all">{e.resource || "—"}</span>
      ),
      className: "max-w-xs",
    },
    {
      header: "Data",
      accessor: (e: AuditEvent) => <DataCell value={e.data} />,
    },
  ];

  const pageNumber = Math.floor(offset / PAGE_SIZE) + 1;
  const hasNext = (events?.length ?? 0) === PAGE_SIZE;
  const hasPrev = offset > 0;

  return (
    <div className="space-y-6 max-w-6xl mx-auto pb-12">
      <div className="flex items-center justify-between">
        <div className="space-y-1">
          <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
            <ScrollText className="h-7 w-7 text-primary" /> Audit
          </h1>
          <p className="text-sm text-muted-foreground">
            Tenant-scoped audit events: tenant CRUD, API key mint/revoke, config changes, etc.
          </p>
        </div>
        <Button
          variant="outline"
          onClick={() => load(tenantId, { limit: PAGE_SIZE, offset })}
          disabled={loading}
          className="shadow-sm"
        >
          <RefreshCw className={`mr-2 h-4 w-4 ${loading ? "animate-spin" : ""}`} /> Refresh
        </Button>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Filter</CardTitle>
          <CardDescription className="text-xs">
            Filter by exact event type (e.g. <code className="font-mono">tenant_created</code>,{" "}
            <code className="font-mono">api_key_created</code>).
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap items-end gap-3">
          <div className="space-y-1">
            <label className="text-[10px] font-bold uppercase text-muted-foreground">
              Event type
            </label>
            <input
              type="text"
              value={filter}
              data-testid="audit-event-type-filter"
              onChange={(e) => setFilter(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") handleFilterApply();
              }}
              placeholder="tenant_created"
              className="h-9 w-56 rounded-md border border-input bg-background px-3 py-2 text-sm focus:ring-2 focus:ring-primary"
            />
          </div>
          <Button onClick={handleFilterApply} disabled={loading} size="sm" className="h-9">
            Apply
          </Button>
          {filter && (
            <Button
              onClick={() => {
                setFilter("");
                setOffset(0);
                load(tenantId, { limit: PAGE_SIZE, offset: 0 });
              }}
              variant="ghost"
              size="sm"
              className="h-9"
            >
              Clear
            </Button>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3 flex flex-row items-center justify-between">
          <div>
            <CardTitle className="text-base">Audit Events</CardTitle>
            <CardDescription className="text-xs">
              Page {pageNumber} · {events?.length ?? 0} event(s)
            </CardDescription>
          </div>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={!hasPrev || loading}
              onClick={() => handlePage("prev")}
              data-testid="audit-prev-page"
            >
              Prev
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={!hasNext || loading}
              onClick={() => handlePage("next")}
              data-testid="audit-next-page"
            >
              Next
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {error && (
            <div className="mb-4 flex items-center gap-2 rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
              <AlertTriangle className="h-4 w-4" />
              <span data-testid="audit-error">{error}</span>
            </div>
          )}
          {loading ? (
            <div className="py-12 text-center">
              <RefreshCw className="mx-auto h-8 w-8 animate-spin text-muted-foreground/40" />
              <p className="mt-4 text-sm text-muted-foreground animate-pulse">
                Loading audit events…
              </p>
            </div>
          ) : (
            <DataTable
              columns={columns}
              data={events ?? []}
              emptyMessage="No audit events recorded yet"
            />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
