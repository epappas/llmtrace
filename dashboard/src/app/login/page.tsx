"use client";

import { Suspense, useEffect, useState, type FormEvent } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Shield } from "lucide-react";

function LoginForm(): React.ReactElement {
  const router = useRouter();
  const search = useSearchParams();
  const next = search.get("next") || "/";
  const [username, setUsername] = useState("");
  const [adminKey, setAdminKey] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  // Pre-fill the username field with the seeded value so operators don't
  // have to guess. Username is a low-secrecy identifier (the admin key is
  // the real secret), so exposing it via /api/auth/identity is acceptable
  // and avoids friction. Field stays editable in case the operator wants
  // to confirm by typing.
  useEffect(() => {
    let cancelled = false;
    fetch("/api/auth/identity", { cache: "no-store" })
      .then((res) => (res.ok ? res.json() : null))
      .then((body: { username?: string } | null) => {
        if (cancelled || !body?.username) return;
        setUsername(body.username);
      })
      .catch(() => {
        // Identity hint is non-critical; on failure the operator just types
        // the username manually.
      });
    return () => {
      cancelled = true;
    };
  }, []);

  async function onSubmit(e: FormEvent<HTMLFormElement>): Promise<void> {
    e.preventDefault();
    if (!username || !adminKey) {
      setError("Username and admin key are required");
      return;
    }
    setError(null);
    setPending(true);
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, admin_key: adminKey }),
      });
      if (res.ok) {
        router.replace(next);
        router.refresh();
        return;
      }
      const body = (await res.json().catch(() => null)) as { error?: string } | null;
      setError(body?.error ?? `Login failed (${res.status})`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setPending(false);
    }
  }

  return (
    <form
      onSubmit={onSubmit}
      className="w-full max-w-sm space-y-6 rounded-lg border bg-card p-8 shadow-sm"
    >
      <div className="flex flex-col items-center gap-2">
        <Shield className="h-8 w-8 text-primary" />
        <h1 className="text-xl font-semibold">LLMTrace Dashboard</h1>
        <p className="text-sm text-muted-foreground">
          Sign in with the credentials seeded at deployment time
        </p>
      </div>

      <div className="space-y-2">
        <label htmlFor="username" className="text-sm font-medium">
          Username
        </label>
        <input
          id="username"
          name="username"
          type="text"
          autoComplete="username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          className="w-full rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
          data-testid="login-username"
        />
      </div>

      <div className="space-y-2">
        <label htmlFor="admin_key" className="text-sm font-medium">
          Admin key
        </label>
        <input
          id="admin_key"
          name="admin_key"
          type="password"
          autoComplete="current-password"
          autoFocus
          value={adminKey}
          onChange={(e) => setAdminKey(e.target.value)}
          className="w-full rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
          data-testid="login-admin-key"
        />
      </div>

      {error && (
        <p
          role="alert"
          className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
          data-testid="login-error"
        >
          {error}
        </p>
      )}

      <button
        type="submit"
        disabled={pending}
        className="w-full rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground disabled:opacity-50"
        data-testid="login-submit"
      >
        {pending ? "Signing in..." : "Sign in"}
      </button>

      <p className="text-center text-xs text-muted-foreground">
        Rotate the admin key via the <code>rotate-admin-key</code> workflow.
      </p>
    </form>
  );
}

export default function LoginPage(): React.ReactElement {
  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-4">
      <Suspense fallback={null}>
        <LoginForm />
      </Suspense>
    </div>
  );
}
