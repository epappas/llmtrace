"""Unit tests for `rotate_admin_key` and the `rotate_admin_after_bootstrap`
post-step in `provision()`.

These tests mock only the Basilica SDK HTTP boundary (`BasilicaClient`'s
`create_deployment`, `delete_deployment`, `get_deployment` methods). The
rotation logic itself runs unmodified.
"""

from __future__ import annotations

import dataclasses
import unittest
from typing import Optional
from unittest.mock import MagicMock

from deployments.basilica import lifecycle


def _replicas(ready: int, desired: int) -> MagicMock:
    obj = MagicMock()
    obj.ready = ready
    obj.desired = desired
    return obj


def _deployment_response(
    instance_name: str,
    state: str = "running",
    url: Optional[str] = None,
    ready: int = 1,
    desired: int = 1,
) -> MagicMock:
    obj = MagicMock()
    obj.instance_name = instance_name
    obj.state = state
    obj.url = url or f"https://{instance_name}.deployments.basilica.ai"
    obj.replicas = _replicas(ready=ready, desired=desired)
    obj.phase = "ready"
    obj.message = None
    return obj


def _proxy_spec() -> lifecycle.ComponentSpec:
    return lifecycle.ComponentSpec(
        image="ghcr.io/techlab-innov/llmtrace-proxy:latest",
        port=8080,
        cpu="2",
        memory="4Gi",
        replicas=1,
        env={
            "LLMTRACE_UPSTREAM_URL": "https://api.openai.com",
            "LLMTRACE_AUTH_ADMIN_KEY": "llmt_oldkey",
            "LLMTRACE_AUTH_ENABLED": "true",
        },
        startup_timeout_seconds=10,
        startup_initial_delay_seconds=0,
        startup_period_seconds=1,
    )


def _dashboard_spec() -> lifecycle.ComponentSpec:
    return lifecycle.ComponentSpec(
        image="ghcr.io/techlab-innov/llmtrace-dashboard:latest",
        port=3000,
        cpu="1",
        memory="1Gi",
        replicas=1,
        env={},
        startup_timeout_seconds=10,
        startup_initial_delay_seconds=0,
        startup_period_seconds=1,
    )


class RotateAdminKeyTests(unittest.TestCase):
    def test_rotation_deletes_old_creates_new_with_new_key(self) -> None:
        client = MagicMock()
        new_proxy_id = "uuid-rotated"
        client.create_deployment.return_value = _deployment_response(new_proxy_id)
        client.get_deployment.return_value = _deployment_response(new_proxy_id)

        result = lifecycle.rotate_admin_key(
            tenant_id="acme",
            proxy_instance_id="uuid-old",
            proxy_spec=_proxy_spec(),
            client=client,
        )

        client.delete_deployment.assert_called_once_with("uuid-old")
        client.create_deployment.assert_called_once()
        kwargs = client.create_deployment.call_args.kwargs
        # Rotation injected a fresh llmt_<64-hex> different from the old key.
        self.assertTrue(kwargs["env"]["LLMTRACE_AUTH_ADMIN_KEY"].startswith("llmt_"))
        self.assertNotEqual(
            kwargs["env"]["LLMTRACE_AUTH_ADMIN_KEY"], "llmt_oldkey"
        )
        self.assertEqual(kwargs["env"]["LLMTRACE_AUTH_ENABLED"], "true")
        # Post-#259 the friendly name is templated against the Basilica
        # slug (deterministic from the tenant_id), not the raw tenant_id.
        expected_slug = lifecycle._basilica_slug("acme")
        self.assertEqual(kwargs["instance_name"], f"llmtrace-proxy-{expected_slug}")
        self.assertEqual(result.tenant_id, "acme")
        self.assertEqual(result.proxy.instance_id, new_proxy_id)
        self.assertEqual(result.admin_key, kwargs["env"]["LLMTRACE_AUTH_ADMIN_KEY"])

    def test_rotation_uses_supplied_new_key(self) -> None:
        client = MagicMock()
        client.create_deployment.return_value = _deployment_response("uuid-new")
        client.get_deployment.return_value = _deployment_response("uuid-new")
        supplied = "llmt_" + "a" * 64

        result = lifecycle.rotate_admin_key(
            tenant_id="acme",
            proxy_instance_id="uuid-old",
            proxy_spec=_proxy_spec(),
            new_key=supplied,
            client=client,
        )

        self.assertEqual(result.admin_key, supplied)
        kwargs = client.create_deployment.call_args.kwargs
        self.assertEqual(kwargs["env"]["LLMTRACE_AUTH_ADMIN_KEY"], supplied)

    def test_rotation_rejects_missing_proxy_id(self) -> None:
        client = MagicMock()
        with self.assertRaises(ValueError):
            lifecycle.rotate_admin_key(
                tenant_id="acme",
                proxy_instance_id="",
                proxy_spec=_proxy_spec(),
                client=client,
            )
        client.delete_deployment.assert_not_called()
        client.create_deployment.assert_not_called()

    def test_rotation_propagates_invalid_tenant_id(self) -> None:
        # Post-#259 the validator accepts arbitrary user identifiers
        # (uppercase, emails, UUIDs) and only rejects empty / whitespace /
        # control-char input. We still want a ValueError to short-circuit
        # the delete+recreate, so feed a value the validator rejects.
        client = MagicMock()
        with self.assertRaises(ValueError):
            lifecycle.rotate_admin_key(
                tenant_id="has space",
                proxy_instance_id="uuid-old",
                proxy_spec=_proxy_spec(),
                client=client,
            )
        client.delete_deployment.assert_not_called()

    def test_rotation_uses_custom_name_template(self) -> None:
        client = MagicMock()
        client.create_deployment.return_value = _deployment_response("uuid-new")
        client.get_deployment.return_value = _deployment_response("uuid-new")

        lifecycle.rotate_admin_key(
            tenant_id="acme",
            proxy_instance_id="uuid-old",
            proxy_spec=_proxy_spec(),
            proxy_name_template="custom-{tenant_id}-proxy",
            client=client,
        )

        kwargs = client.create_deployment.call_args.kwargs
        expected_slug = lifecycle._basilica_slug("acme")
        self.assertEqual(kwargs["instance_name"], f"custom-{expected_slug}-proxy")


class ProvisionWithRotateAfterBootstrapTests(unittest.TestCase):
    def _build_spec(self, rotate: bool) -> lifecycle.TenantSpec:
        return lifecycle.TenantSpec(
            tenant_id="acme",
            proxy=_proxy_spec(),
            dashboard=_dashboard_spec(),
            api_key="llmt_bootstrap",
            rotate_admin_after_bootstrap=rotate,
        )

    def test_off_by_default(self) -> None:
        spec = lifecycle.TenantSpec(
            tenant_id="acme",
            proxy=_proxy_spec(),
            dashboard=_dashboard_spec(),
        )
        self.assertFalse(spec.rotate_admin_after_bootstrap)

    def test_no_rotation_when_flag_off(self) -> None:
        client = MagicMock()
        # provision creates proxy then dashboard
        client.create_deployment.side_effect = [
            _deployment_response("uuid-proxy-1"),
            _deployment_response("uuid-dashboard-1"),
        ]
        client.get_deployment.side_effect = [
            _deployment_response("uuid-proxy-1"),
            _deployment_response("uuid-dashboard-1"),
        ]

        result = lifecycle.provision(self._build_spec(rotate=False), client=client)

        self.assertEqual(client.create_deployment.call_count, 2)
        client.delete_deployment.assert_not_called()
        self.assertEqual(result.api_key, "llmt_bootstrap")
        self.assertEqual(result.proxy.instance_id, "uuid-proxy-1")

    def test_rotation_runs_when_flag_on(self) -> None:
        client = MagicMock()
        # provision: proxy create, dashboard create.
        # rotation: delete old proxy, create new proxy.
        # _wait_until_ready will call get_deployment on each created instance.
        client.create_deployment.side_effect = [
            _deployment_response("uuid-proxy-1"),
            _deployment_response("uuid-dashboard-1"),
            _deployment_response("uuid-proxy-2"),
        ]
        client.get_deployment.side_effect = [
            _deployment_response("uuid-proxy-1"),
            _deployment_response("uuid-dashboard-1"),
            _deployment_response("uuid-proxy-2"),
        ]

        result = lifecycle.provision(self._build_spec(rotate=True), client=client)

        # delete called for the bootstrap proxy
        client.delete_deployment.assert_called_once_with("uuid-proxy-1")
        # 3 create calls: bootstrap proxy, bootstrap dashboard, rotated proxy
        self.assertEqual(client.create_deployment.call_count, 3)
        # final proxy is the rotated one, api_key changed off bootstrap
        self.assertEqual(result.proxy.instance_id, "uuid-proxy-2")
        self.assertNotEqual(result.api_key, "llmt_bootstrap")
        self.assertTrue(result.api_key.startswith("llmt_"))
        rotated_kwargs = client.create_deployment.call_args_list[2].kwargs
        self.assertEqual(
            rotated_kwargs["env"]["LLMTRACE_AUTH_ADMIN_KEY"], result.api_key
        )

    def test_rotation_skipped_when_auth_disabled(self) -> None:
        spec = dataclasses.replace(
            self._build_spec(rotate=True),
            enable_proxy_auth=False,
            api_key=None,
        )
        client = MagicMock()
        client.create_deployment.side_effect = [
            _deployment_response("uuid-proxy-1"),
            _deployment_response("uuid-dashboard-1"),
        ]
        client.get_deployment.side_effect = [
            _deployment_response("uuid-proxy-1"),
            _deployment_response("uuid-dashboard-1"),
        ]

        result = lifecycle.provision(spec, client=client)

        # Auth disabled means no admin key exists to rotate — skip.
        client.delete_deployment.assert_not_called()
        self.assertEqual(client.create_deployment.call_count, 2)
        self.assertIsNone(result.api_key)


if __name__ == "__main__":
    unittest.main()
