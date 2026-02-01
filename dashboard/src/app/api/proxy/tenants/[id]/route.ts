import { NextRequest } from "next/server";
import { proxyGet, proxyMutate } from "@/lib/proxy-helpers";

export async function GET(
  req: NextRequest,
  { params }: { params: { id: string } },
) {
  return proxyGet(req, `/api/v1/tenants/${params.id}`);
}

export async function PUT(
  req: NextRequest,
  { params }: { params: { id: string } },
) {
  return proxyMutate(req, `/api/v1/tenants/${params.id}`, "PUT");
}

export async function DELETE(
  req: NextRequest,
  { params }: { params: { id: string } },
) {
  return proxyMutate(req, `/api/v1/tenants/${params.id}`, "DELETE");
}
