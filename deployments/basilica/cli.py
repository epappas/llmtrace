"""CLI for tenant lifecycle on Basilica.

The Basilica SDK addresses deployments by server-assigned UUID. The CLI
mirrors that contract: `provision` returns UUIDs; subsequent commands
(`status`, `update`, `deprovision`) require the caller to supply them.
The caller is expected to persist the `tenant_id → (proxy_instance_id,
dashboard_instance_id)` mapping somewhere (app DB, workflow output store).

Configuration is loaded from a YAML or JSON file (or inline JSON). See
`deployments/basilica/configs/examples/` for templates. `${VAR}` and
`${VAR:-default}` placeholders in string values are substituted from
process environment at load time — use this to inject secrets without
writing them to the config file.

Output is JSON to stdout. Logs to stderr. Exit codes: 0 success,
2 usage error, 3 lifecycle error.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import os
import pathlib
import re
import sys
from typing import Any

import yaml

from . import lifecycle

LOGGER = logging.getLogger("deployments.basilica.cli")

_ENV_PLACEHOLDER = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _substitute_env(value: Any) -> Any:
    """Recursively substitute `${VAR}` / `${VAR:-default}` in string values."""
    if isinstance(value, str):
        def repl(match: re.Match[str]) -> str:
            name, default = match.group(1), match.group(2)
            resolved = os.environ.get(name)
            if resolved is not None:
                return resolved
            if default is not None:
                return default
            raise KeyError(f"env var {name!r} required by config is not set")

        return _ENV_PLACEHOLDER.sub(repl, value)
    if isinstance(value, dict):
        return {k: _substitute_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute_env(v) for v in value]
    return value


def _load_config(path: str | None, inline_json: str | None) -> dict[str, Any]:
    if path and inline_json:
        raise SystemExit("--config and --config-json are mutually exclusive")
    if not path and not inline_json:
        raise SystemExit("one of --config or --config-json is required")
    if inline_json:
        raw = json.loads(inline_json)
    else:
        text = pathlib.Path(path).read_text()
        raw = yaml.safe_load(text)
    if not isinstance(raw, dict):
        raise SystemExit(
            f"config must be a mapping at the top level, got {type(raw).__name__}"
        )
    return _substitute_env(raw)


def _component_from_dict(data: dict[str, Any], label: str) -> lifecycle.ComponentSpec:
    required = {"image", "port", "cpu", "memory", "replicas", "env"}
    missing = required - data.keys()
    if missing:
        raise SystemExit(
            f"component {label!r} is missing required keys: {sorted(missing)}"
        )
    env = data["env"] or {}
    if not isinstance(env, dict):
        raise SystemExit(f"component {label!r}: 'env' must be a mapping")
    env_strs = {str(k): str(v) for k, v in env.items()}
    kwargs: dict[str, Any] = {
        "image": str(data["image"]),
        "port": int(data["port"]),
        "cpu": str(data["cpu"]),
        "memory": str(data["memory"]),
        "replicas": int(data["replicas"]),
        "env": env_strs,
    }
    optional = {
        "health_check_path": str,
        "startup_timeout_seconds": int,
        "startup_initial_delay_seconds": int,
        "startup_period_seconds": int,
        "startup_failure_threshold": int,
        "liveness_period_seconds": int,
        "liveness_failure_threshold": int,
        "readiness_period_seconds": int,
        "readiness_failure_threshold": int,
    }
    for key, caster in optional.items():
        if key in data:
            kwargs[key] = caster(data[key])
    return lifecycle.ComponentSpec(**kwargs)


def _tenant_spec_from_config(tenant_id: str, cfg: dict[str, Any]) -> lifecycle.TenantSpec:
    if "proxy" not in cfg or "dashboard" not in cfg:
        raise SystemExit(
            "config must contain top-level 'proxy' and 'dashboard' mappings"
        )
    proxy = _component_from_dict(cfg["proxy"], "proxy")
    dashboard = _component_from_dict(cfg["dashboard"], "dashboard")
    kwargs: dict[str, Any] = {
        "tenant_id": tenant_id,
        "proxy": proxy,
        "dashboard": dashboard,
    }
    for key in (
        "proxy_name_template",
        "dashboard_name_template",
        "inject_proxy_url_into_dashboard",
        "proxy_url_env_var",
    ):
        if key in cfg:
            kwargs[key] = cfg[key]
    return lifecycle.TenantSpec(**kwargs)


def _serialise(instances: lifecycle.TenantInstances) -> dict[str, Any]:
    def view(info: lifecycle.InstanceInfo | None) -> dict[str, Any] | None:
        return dataclasses.asdict(info) if info is not None else None

    return {
        "tenant_id": instances.tenant_id,
        "proxy": view(instances.proxy),
        "dashboard": view(instances.dashboard),
        "proxy_instance_id": instances.proxy.instance_id if instances.proxy else None,
        "dashboard_instance_id": instances.dashboard.instance_id if instances.dashboard else None,
        "proxy_url": instances.proxy.url if instances.proxy else None,
        "dashboard_url": instances.dashboard.url if instances.dashboard else None,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="deployments.basilica.cli",
        description="LLMTrace tenant lifecycle on Basilica",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    sub = parser.add_subparsers(dest="action", required=True)

    def add_tenant(p: argparse.ArgumentParser) -> None:
        p.add_argument("--tenant-id", required=True)

    def add_config(p: argparse.ArgumentParser) -> None:
        g = p.add_mutually_exclusive_group(required=True)
        g.add_argument("--config", help="Path to a YAML or JSON config file")
        g.add_argument("--config-json", help="Inline JSON config")

    def add_ids(p: argparse.ArgumentParser, required: bool) -> None:
        p.add_argument(
            "--proxy-instance-id",
            required=required,
            default=None,
            help="Basilica UUID for the existing proxy deployment",
        )
        p.add_argument(
            "--dashboard-instance-id",
            required=required,
            default=None,
            help="Basilica UUID for the existing dashboard deployment",
        )

    p_prov = sub.add_parser(
        "provision",
        help="Create a fresh deployment pair (always creates — caller is responsible for de-duping)",
    )
    add_tenant(p_prov)
    add_config(p_prov)

    p_upd = sub.add_parser("update", help="Restart or recreate the pair (UUIDs required)")
    add_tenant(p_upd)
    add_config(p_upd)
    add_ids(p_upd, required=True)
    p_upd.add_argument(
        "--strategy", default="recreate", choices=["restart", "recreate"]
    )

    p_st = sub.add_parser("status", help="Read state for given UUIDs")
    add_tenant(p_st)
    add_ids(p_st, required=False)

    p_dep = sub.add_parser("deprovision", help="Delete given UUIDs (idempotent)")
    add_tenant(p_dep)
    add_ids(p_dep, required=False)

    return parser


def _dispatch(args: argparse.Namespace) -> lifecycle.TenantInstances:
    if args.action == "provision":
        cfg = _load_config(args.config, args.config_json)
        spec = _tenant_spec_from_config(args.tenant_id, cfg)
        return lifecycle.provision(spec)
    if args.action == "update":
        cfg = _load_config(args.config, args.config_json)
        spec = _tenant_spec_from_config(args.tenant_id, cfg)
        return lifecycle.update(
            spec,
            proxy_instance_id=args.proxy_instance_id,
            dashboard_instance_id=args.dashboard_instance_id,
            strategy=args.strategy,
        )
    if args.action == "status":
        return lifecycle.status(
            tenant_id=args.tenant_id,
            proxy_instance_id=args.proxy_instance_id,
            dashboard_instance_id=args.dashboard_instance_id,
        )
    if args.action == "deprovision":
        return lifecycle.deprovision(
            tenant_id=args.tenant_id,
            proxy_instance_id=args.proxy_instance_id,
            dashboard_instance_id=args.dashboard_instance_id,
        )
    raise SystemExit(f"unknown action {args.action!r}")


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    try:
        result = _dispatch(args)
    except (ValueError, RuntimeError, TimeoutError, KeyError) as exc:
        LOGGER.error("lifecycle failure: %s", exc)
        json.dump({"error": str(exc), "action": args.action}, sys.stdout)
        sys.stdout.write("\n")
        return 3
    json.dump(_serialise(result), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
