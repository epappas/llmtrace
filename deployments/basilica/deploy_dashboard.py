#!/usr/bin/env python3
"""Deploy LLMTrace dashboard to Basilica."""

import os
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
load_dotenv(SCRIPT_DIR / ".env")

PROXY_ID_FILE = SCRIPT_DIR / ".deployment_id"
DASHBOARD_ID_FILE = SCRIPT_DIR / ".dashboard_deployment_id"


def resolve_proxy_url() -> str:
    """Resolve the proxy URL from env or .deployment_id."""
    url = os.environ.get("LLMTRACE_PROXY_URL", "").strip()
    if url:
        return url

    if not PROXY_ID_FILE.exists():
        print("ERROR: LLMTRACE_PROXY_URL not set and .deployment_id not found.")
        print("Deploy the proxy first or set LLMTRACE_PROXY_URL in .env.")
        sys.exit(1)

    from basilica import BasilicaClient

    api_key = os.environ.get("BASILICA_API_TOKEN")
    if not api_key:
        print("ERROR: BASILICA_API_TOKEN not set. Copy .env.example to .env.")
        sys.exit(1)

    client = BasilicaClient(api_key=api_key)
    proxy_id = PROXY_ID_FILE.read_text().strip()

    try:
        detail = client.get_deployment(proxy_id)
    except (KeyError, Exception) as e:
        print(f"Failed to get proxy deployment '{proxy_id}': {e}")
        sys.exit(1)

    if not detail.url:
        print(f"ERROR: Proxy deployment '{proxy_id}' has no URL yet.")
        sys.exit(1)

    return detail.url


def validate_env() -> dict[str, str]:
    """Validate required env vars and return dashboard config."""
    api_key = os.environ.get("BASILICA_API_TOKEN")
    if not api_key:
        print("ERROR: BASILICA_API_TOKEN not set. Copy .env.example to .env.")
        sys.exit(1)

    return {
        "api_key": api_key,
        "image": os.environ.get("DASHBOARD_IMAGE", "ghcr.io/epappas/llmtrace-dashboard:latest"),
        "name": os.environ.get("DASHBOARD_DEPLOYMENT_NAME", "llmtrace-dashboard"),
        "cpu": os.environ.get("DASHBOARD_CPU", "1"),
        "memory": os.environ.get("DASHBOARD_MEMORY", "1Gi"),
        "replicas": int(os.environ.get("DASHBOARD_REPLICAS", "1")),
    }


def deploy() -> None:
    """Deploy the LLMTrace dashboard to Basilica."""
    from basilica import BasilicaClient, HealthCheckConfig, ProbeConfig

    cfg = validate_env()
    proxy_url = resolve_proxy_url()

    container_env: dict[str, str] = {
        "LLMTRACE_PROXY_URL": proxy_url,
        "HOSTNAME": "0.0.0.0",
        "NODE_ENV": "production",
    }

    admin_key = os.environ.get("LLMTRACE_AUTH_ADMIN_KEY", "").strip()
    if admin_key:
        container_env["LLMTRACE_AUTH_ADMIN_KEY"] = admin_key

    print(f"Deploying {cfg['name']} to Basilica...")
    print(f"  Image:     {cfg['image']}")
    print(f"  CPU:       {cfg['cpu']}")
    print(f"  Memory:    {cfg['memory']}")
    print(f"  Replicas:  {cfg['replicas']}")
    print(f"  Proxy URL: {proxy_url}")
    print(f"  Env vars:  {', '.join(sorted(container_env.keys()))}")

    client = BasilicaClient(api_key=cfg["api_key"])

    health_check = HealthCheckConfig(
        startup=ProbeConfig(
            path="/health",
            port=3000,
            initial_delay_seconds=10,
            period_seconds=10,
            failure_threshold=10,
        ),
        liveness=ProbeConfig(
            path="/health",
            port=3000,
            period_seconds=30,
            failure_threshold=3,
        ),
        readiness=ProbeConfig(
            path="/health",
            port=3000,
            period_seconds=10,
            failure_threshold=3,
        ),
    )

    response = client.create_deployment(
        instance_name=cfg["name"],
        image=cfg["image"],
        replicas=cfg["replicas"],
        port=3000,
        env=container_env,
        cpu=cfg["cpu"],
        memory=cfg["memory"],
        health_check=health_check,
    )

    deployment_id = response.instance_name
    DASHBOARD_ID_FILE.write_text(deployment_id)

    print(f"\nDeployment created: {deployment_id}")
    print(f"  State: {response.state}")
    print(f"  URL:   {response.url}")
    print(f"  (ID saved to {DASHBOARD_ID_FILE})")
    print("Waiting for deployment to become ready...")

    max_wait = 300
    poll_interval = 10
    elapsed = 0

    while elapsed < max_wait:
        status = client.get_deployment(deployment_id)
        state = status.state
        replicas = status.replicas
        print(f"  [{elapsed}s] State: {state}  Replicas: {replicas.ready}/{replicas.desired}")

        if state in ("running", "Active") and replicas.ready >= replicas.desired:
            print(f"\nDashboard is ready!")
            print(f"  URL: {status.url}")
            return

        if state in ("failed", "error"):
            print(f"\nERROR: Dashboard deployment failed with state: {state}")
            if status.message:
                print(f"  Message: {status.message}")
            sys.exit(1)

        time.sleep(poll_interval)
        elapsed += poll_interval

    print(f"\nWARNING: Dashboard did not become ready within {max_wait}s.")
    print("  Check status: python status.py")
    sys.exit(1)


if __name__ == "__main__":
    deploy()
