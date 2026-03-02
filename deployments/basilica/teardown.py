#!/usr/bin/env python3
"""Teardown (delete) LLMTrace deployments from Basilica."""

import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
load_dotenv(SCRIPT_DIR / ".env")

PROXY_ID_FILE = SCRIPT_DIR / ".deployment_id"
DASHBOARD_ID_FILE = SCRIPT_DIR / ".dashboard_deployment_id"


def resolve_deployment_id(id_file: Path) -> str | None:
    """Read deployment ID from file."""
    if id_file.exists():
        return id_file.read_text().strip()
    return None


def teardown_deployment(client: "BasilicaClient", deployment_id: str, id_file: Path, label: str) -> None:
    """Teardown a single deployment after user confirmation."""
    try:
        detail = client.get_deployment(deployment_id)
    except (KeyError, Exception) as e:
        print(f"  Failed to get {label} '{deployment_id}': {e}")
        return

    print(f"\n{label}: {detail.instance_name}")
    print(f"  State: {detail.state}")
    print(f"  URL:   {detail.url}")

    confirm = input(f"Delete {label.lower()}? [y/N] ").strip().lower()
    if confirm != "y":
        print(f"  Skipped {label.lower()}.")
        return

    result = client.delete_deployment(deployment_id)
    print(f"  Deleted '{result.instance_name}'. State: {result.state}")
    if result.message:
        print(f"  Message: {result.message}")

    if id_file.exists():
        id_file.unlink()
        print(f"  Removed {id_file}")


def teardown() -> None:
    """Delete LLMTrace deployments from Basilica."""
    from basilica import BasilicaClient

    api_key = os.environ.get("BASILICA_API_TOKEN")
    if not api_key:
        print("ERROR: BASILICA_API_TOKEN not set. Copy .env.example to .env.")
        sys.exit(1)

    client = BasilicaClient(api_key=api_key)

    proxy_id = resolve_deployment_id(PROXY_ID_FILE)
    dashboard_id = resolve_deployment_id(DASHBOARD_ID_FILE)

    if not proxy_id and not dashboard_id:
        print("No deployments found (.deployment_id / .dashboard_deployment_id missing).")
        sys.exit(1)

    if dashboard_id:
        teardown_deployment(client, dashboard_id, DASHBOARD_ID_FILE, "Dashboard")

    if proxy_id:
        teardown_deployment(client, proxy_id, PROXY_ID_FILE, "Proxy")


if __name__ == "__main__":
    teardown()
