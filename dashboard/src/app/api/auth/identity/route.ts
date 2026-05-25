import { NextResponse } from "next/server";
import { expectedAdminUsername } from "@/lib/auth";

/**
 * Returns the expected admin username for this dashboard so the login form
 * can pre-fill the username field. This is intentionally unauthenticated:
 * the username is a low-secrecy identifier (the password is the admin key),
 * and pre-filling avoids a UX trap where the operator types their account's
 * "alice@acme.example" only to discover the deployment was seeded with
 * "ops-admin" and a typo gives a generic "invalid credentials" error.
 */
export function GET(): NextResponse {
  return NextResponse.json({ username: expectedAdminUsername() });
}
