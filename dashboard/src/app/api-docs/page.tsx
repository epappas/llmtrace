import { ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";

export const dynamic = "force-dynamic";

const SWAGGER_UI_URL = "/api/proxy/swagger-ui/";
const OPENAPI_JSON_URL = "/api/proxy/api-doc/openapi.json";

export default function ApiDocsPage() {
  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <h1 className="text-3xl font-bold">API Endpoints</h1>
        <p className="text-sm text-muted-foreground">
          Interactive OpenAPI documentation served by the LLMTrace proxy. Use the operator
          API key when calling endpoints from your own apps; see the Tenants page for how to
          obtain one.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Swagger UI</CardTitle>
          <CardDescription>
            Embedded Swagger UI rendered from the proxy&apos;s OpenAPI document.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <Button asChild variant="outline" size="sm">
              <a href={SWAGGER_UI_URL} target="_blank" rel="noreferrer">
                <ExternalLink className="mr-2 h-4 w-4" />
                Open Swagger UI
              </a>
            </Button>
            <Button asChild variant="outline" size="sm">
              <a href={OPENAPI_JSON_URL} target="_blank" rel="noreferrer">
                <ExternalLink className="mr-2 h-4 w-4" />
                Open OpenAPI JSON
              </a>
            </Button>
            <span className="text-xs text-muted-foreground">
              Served via dashboard proxy routes
            </span>
          </div>

          <div className="rounded-md border">
            <iframe
              title="LLMTrace Swagger UI"
              src={SWAGGER_UI_URL}
              data-testid="api-docs-swagger-iframe"
              className="h-[70vh] w-full rounded-md"
            />
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
