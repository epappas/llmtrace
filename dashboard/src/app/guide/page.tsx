"use client";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

type GuideSection = {
  title: string;
  route: string;
  image: string;
  description: string;
  learn: string;
};

const sections: GuideSection[] = [
  {
    title: "Overview",
    route: "/",
    image: "/guide/overview.png",
    description: "Global metrics across tenants, trace volume, security findings, and spend summaries.",
    learn: "Start here to understand overall health and where to drill down next.",
  },
  {
    title: "Traces",
    route: "/traces",
    image: "/guide/traces.png",
    description: "Filter and inspect trace history by provider, model, trace ID, and date.",
    learn: "Use this page for incident triage and audit review.",
  },
  {
    title: "Trace Details",
    route: "/traces/:id",
    image: "/guide/trace-details.png",
    description: "Span-level request/response details, token stats, and security annotations.",
    learn: "Validate model behavior and investigate suspicious prompt chains.",
  },
  {
    title: "Security",
    route: "/security",
    image: "/guide/security.png",
    description: "Security findings distribution and recent flagged events.",
    learn: "Track prompt-injection and other policy violations over time.",
  },
  {
    title: "Costs",
    route: "/costs",
    image: "/guide/costs.png",
    description: "Budget visibility and usage windows (when cost caps are enabled).",
    learn: "Monitor spend and identify bursts before they become overruns.",
  },
  {
    title: "Tenants",
    route: "/tenants",
    image: "/guide/tenants.png",
    description: "Tenant administration, token management, API key generation, and config tuning.",
    learn: "Configure isolation boundaries and role-based access controls.",
  },
  {
    title: "Tenant Config",
    route: "/tenants/config",
    image: "/guide/tenants-config.png",
    description: "Tenant-level monitoring scope, thresholds, and feature flag controls.",
    learn: "Tune enforcement per tenant without changing global proxy defaults.",
  },
  {
    title: "Compliance",
    route: "/compliance",
    image: "/guide/compliance.png",
    description: "Generate and review SOC2/GDPR/HIPAA style reports.",
    learn: "Use the report viewer for audit evidence and export JSON when needed.",
  },
  {
    title: "Compliance Report Viewer",
    route: "/compliance (report open)",
    image: "/guide/compliance-report-viewer.png",
    description: "Expanded generated report with controls for export, raw JSON, and close.",
    learn: "Review auditor-facing evidence in the same workflow used for compliance generation.",
  },
  {
    title: "Compliance Raw JSON",
    route: "/compliance (report raw)",
    image: "/guide/compliance-report-viewer-raw.png",
    description: "Raw report payload view for programmatic auditing and downstream integrations.",
    learn: "Validate the exact structured report content before export/automation.",
  },
  {
    title: "Settings",
    route: "/settings",
    image: "/guide/settings.png",
    description: "Environment setup, backend connectivity checks, and embedded Swagger docs.",
    learn: "Verify API availability and inspect endpoint contracts directly.",
  },
];

export default function GuidePage() {
  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <h1 className="text-3xl font-bold">Dashboard Guide</h1>
        <p className="text-muted-foreground">
          Visual walkthrough of LLMTrace dashboard functionality. Screenshots are captured with Playwright from a running stack.
        </p>
      </div>

      {sections.map((section) => (
        <Card key={section.title} className="overflow-hidden">
          <CardHeader>
            <CardTitle>{section.title}</CardTitle>
            <CardDescription>
              Route: <span className="font-mono text-xs">{section.route}</span>
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <img
              src={section.image}
              alt={`${section.title} screenshot`}
              className="w-full rounded-md border"
            />
            <p className="text-sm">{section.description}</p>
            <p className="text-sm text-muted-foreground">{section.learn}</p>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
