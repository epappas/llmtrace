import { NextRequest } from "next/server";
import { proxyGet, proxyMutate } from "@/lib/proxy-helpers";

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  return proxyGet(req, `/api/v1/tenants/${id}`);
}

export async function PUT(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  return proxyMutate(req, `/api/v1/tenants/${id}`, "PUT");
}

export async function DELETE(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  return proxyMutate(req, `/api/v1/tenants/${id}`, "DELETE");
}
