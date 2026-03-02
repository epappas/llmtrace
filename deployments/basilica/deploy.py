#!/usr/bin/env python3
"""Deploy LLMTrace proxy to Basilica."""

import os
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
load_dotenv(SCRIPT_DIR / ".env")

REQUIRED_VARS = ["BASILICA_API_TOKEN", "LLMTRACE_UPSTREAM_URL"]

CONTAINER_ENV_PREFIXES = ("LLMTRACE_", "RUST_LOG")


def validate_env() -> dict[str, str]:
    """Validate required environment variables and return config."""
    missing = [v for v in REQUIRED_VARS if not os.environ.get(v)]
    if missing:
        print(f"ERROR: Missing required environment variables: {', '.join(missing)}")
        print("Copy .env.example to .env and fill in the values.")
        sys.exit(1)

    return {
        "api_key": os.environ["BASILICA_API_TOKEN"],
        "image": os.environ.get("LLMTRACE_IMAGE", "ghcr.io/epappas/llmtrace-proxy:latest"),
        "name": os.environ.get("DEPLOYMENT_NAME", "llmtrace-proxy"),
        "cpu": os.environ.get("DEPLOY_CPU", "2"),
        "memory": os.environ.get("DEPLOY_MEMORY", "4Gi"),
        "replicas": int(os.environ.get("DEPLOY_REPLICAS", "1")),
    }


def collect_container_env() -> dict[str, str]:
    """Collect LLMTRACE_* and RUST_LOG env vars to forward to the container."""
    return {
        key: value
        for key, value in os.environ.items()
        if key.startswith(CONTAINER_ENV_PREFIXES)
    }


def deploy() -> None:
    """Deploy the LLMTrace proxy to Basilica."""
    from basilica import BasilicaClient, HealthCheckConfig, ProbeConfig

    cfg = validate_env()
    container_env = collect_container_env()

    print(f"Deploying {cfg['name']} to Basilica...")
    print(f"  Image:    {cfg['image']}")
    print(f"  CPU:      {cfg['cpu']}")
    print(f"  Memory:   {cfg['memory']}")
    print(f"  Replicas: {cfg['replicas']}")
    print(f"  Env vars: {', '.join(sorted(container_env.keys()))}")

    client = BasilicaClient(api_key=cfg["api_key"])

    health_check = HealthCheckConfig(
        startup=ProbeConfig(
            path="/health",
            port=8080,
            initial_delay_seconds=30,
            period_seconds=30,
            failure_threshold=15,
        ),
        liveness=ProbeConfig(
            path="/health",
            port=8080,
            period_seconds=30,
            failure_threshold=3,
        ),
        readiness=ProbeConfig(
            path="/health",
            port=8080,
            period_seconds=10,
            failure_threshold=3,
        ),
    )

    response = client.create_deployment(
        instance_name=cfg["name"],
        image=cfg["image"],
        replicas=cfg["replicas"],
        port=8080,
        env=container_env,
        cpu=cfg["cpu"],
        memory=cfg["memory"],
        health_check=health_check,
    )

    deployment_id = response.instance_name

    # Persist the deployment ID for status.py and teardown.py
    id_file = SCRIPT_DIR / ".deployment_id"
    id_file.write_text(deployment_id)

    print(f"\nDeployment created: {deployment_id}")
    print(f"  State: {response.state}")
    print(f"  URL:   {response.url}")
    print(f"  (ID saved to {id_file})")
    print("Waiting for deployment to become ready...")

    max_wait = 600
    poll_interval = 15
    elapsed = 0

    while elapsed < max_wait:
        status = client.get_deployment(deployment_id)
        state = status.state
        replicas = status.replicas
        print(f"  [{elapsed}s] State: {state}  Replicas: {replicas.ready}/{replicas.desired}")

        if state in ("running", "Active") and replicas.ready >= replicas.desired:
            print(f"\nDeployment is ready!")
            print(f"  URL: {status.url}")
            return

        if state in ("failed", "error"):
            print(f"\nERROR: Deployment failed with state: {state}")
            if status.message:
                print(f"  Message: {status.message}")
            sys.exit(1)

        time.sleep(poll_interval)
        elapsed += poll_interval

    print(f"\nWARNING: Deployment did not become ready within {max_wait}s.")
    print("  Check status: python status.py")
    sys.exit(1)


if __name__ == "__main__":
    deploy()
