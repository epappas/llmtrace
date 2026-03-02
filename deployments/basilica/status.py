#!/usr/bin/env python3
"""Check the status of LLMTrace deployments on Basilica."""

import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
load_dotenv(SCRIPT_DIR / ".env")

PROXY_ID_FILE = SCRIPT_DIR / ".deployment_id"
DASHBOARD_ID_FILE = SCRIPT_DIR / ".dashboard_deployment_id"


def resolve_deployment_id(id_file: Path, default_name: str) -> str | None:
    """Read deployment ID from file or env."""
    if id_file.exists():
        return id_file.read_text().strip()
    return None


def print_deployment_status(client: "BasilicaClient", deployment_id: str, label: str) -> None:
    """Print status of a single deployment."""
    try:
        detail = client.get_deployment(deployment_id)
    except (KeyError, Exception) as e:
        print(f"  Failed to get {label} '{deployment_id}': {e}")
        return

    replicas = detail.replicas
    print(f"\n{label}: {detail.instance_name}")
    print(f"  State:    {detail.state}")
    print(f"  Replicas: {replicas.ready}/{replicas.desired}")
    print(f"  URL:      {detail.url}")
    if detail.message:
        print(f"  Message:  {detail.message}")
    if detail.progress:
        print(f"  Progress: {detail.progress.current_step} ({detail.progress.elapsed_seconds}s)")
    if detail.pods:
        print("  Pods:")
        for pod in detail.pods:
            print(f"    {pod.name}: {pod.status}")


def status() -> None:
    """Query and display deployment status for proxy and dashboard."""
    from basilica import BasilicaClient

    api_key = os.environ.get("BASILICA_API_TOKEN")
    if not api_key:
        print("ERROR: BASILICA_API_TOKEN not set. Copy .env.example to .env.")
        sys.exit(1)

    client = BasilicaClient(api_key=api_key)

    proxy_id = resolve_deployment_id(PROXY_ID_FILE, "llmtrace-proxy")
    dashboard_id = resolve_deployment_id(DASHBOARD_ID_FILE, "llmtrace-dashboard")

    if not proxy_id and not dashboard_id:
        print("No deployments found. Deploy first with deploy.py or deploy_dashboard.py.")
        result = client.list_deployments()
        if result.deployments:
            print("\nAvailable deployments:")
            for d in result.deployments:
                print(f"  {d.instance_name} - {d.state} - {d.url}")
        sys.exit(1)

    if proxy_id:
        print_deployment_status(client, proxy_id, "Proxy")

    if dashboard_id:
        print_deployment_status(client, dashboard_id, "Dashboard")


if __name__ == "__main__":
    status()
