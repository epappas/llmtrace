"""Unit tests for the ML-preload startup-timeout floor.

The bump is implemented as a pure function (`_apply_ml_preload_startup_floor`)
on `ComponentSpec`, so the tests exercise it directly — no SDK mocking, no
provision flow stubbing. This matches the production code path: every
`_create_component` call site for the proxy runs the spec through the same
helper before handing it to the Basilica SDK.
"""

from __future__ import annotations

import logging
import unittest
from typing import Mapping

from deployments.basilica import lifecycle


def _proxy_spec(
    *, env: Mapping[str, str], startup_timeout_seconds: int
) -> lifecycle.ComponentSpec:
    return lifecycle.ComponentSpec(
        image="ghcr.io/techlab-innov/llmtrace-proxy:latest",
        port=8080,
        cpu="2",
        memory="4Gi",
        replicas=1,
        env=env,
        startup_timeout_seconds=startup_timeout_seconds,
    )


class MLPreloadStartupFloorTests(unittest.TestCase):
    def test_bumps_when_below_floor_and_ml_preload_on(self) -> None:
        spec = _proxy_spec(
            env={"LLMTRACE_ML_ENABLED": "1", "LLMTRACE_ML_PRELOAD": "1"},
            startup_timeout_seconds=600,
        )
        with self.assertLogs(lifecycle.LOGGER, level=logging.WARNING) as captured:
            bumped = lifecycle._apply_ml_preload_startup_floor(
                spec, tenant_id="acme"
            )

        self.assertEqual(
            bumped.startup_timeout_seconds,
            lifecycle.ML_PRELOAD_STARTUP_FLOOR_SECONDS,
        )
        # All other fields preserved.
        self.assertEqual(bumped.image, spec.image)
        self.assertEqual(bumped.env, spec.env)
        self.assertEqual(bumped.port, spec.port)
        # Exactly one warning, mentioning the tenant + the floor.
        self.assertEqual(len(captured.records), 1)
        message = captured.records[0].getMessage()
        self.assertIn("acme", message)
        self.assertIn("600", message)
        self.assertIn(str(lifecycle.ML_PRELOAD_STARTUP_FLOOR_SECONDS), message)

    def test_no_bump_when_caller_value_meets_floor(self) -> None:
        explicit = lifecycle.ML_PRELOAD_STARTUP_FLOOR_SECONDS + 300
        spec = _proxy_spec(
            env={"LLMTRACE_ML_ENABLED": "true", "LLMTRACE_ML_PRELOAD": "yes"},
            startup_timeout_seconds=explicit,
        )
        # `assertNoLogs` is Python 3.10+. Capture and assert empty as a portable
        # alternative that still fails loudly if a warning leaks.
        with self.assertLogs(lifecycle.LOGGER, level=logging.DEBUG) as captured:
            lifecycle.LOGGER.debug("anchor")  # ensure the context has >=1 record
            result = lifecycle._apply_ml_preload_startup_floor(
                spec, tenant_id="acme"
            )

        self.assertIs(result, spec)
        self.assertEqual(result.startup_timeout_seconds, explicit)
        warnings = [r for r in captured.records if r.levelno >= logging.WARNING]
        self.assertEqual(warnings, [])

    def test_no_bump_when_caller_value_equals_floor(self) -> None:
        spec = _proxy_spec(
            env={"LLMTRACE_ML_ENABLED": "1", "LLMTRACE_ML_PRELOAD": "1"},
            startup_timeout_seconds=lifecycle.ML_PRELOAD_STARTUP_FLOOR_SECONDS,
        )
        with self.assertLogs(lifecycle.LOGGER, level=logging.DEBUG) as captured:
            lifecycle.LOGGER.debug("anchor")
            result = lifecycle._apply_ml_preload_startup_floor(
                spec, tenant_id="acme"
            )

        self.assertIs(result, spec)
        warnings = [r for r in captured.records if r.levelno >= logging.WARNING]
        self.assertEqual(warnings, [])

    def test_no_bump_when_ml_preload_off(self) -> None:
        spec = _proxy_spec(
            env={"LLMTRACE_ML_ENABLED": "1", "LLMTRACE_ML_PRELOAD": "0"},
            startup_timeout_seconds=300,
        )
        with self.assertLogs(lifecycle.LOGGER, level=logging.DEBUG) as captured:
            lifecycle.LOGGER.debug("anchor")
            result = lifecycle._apply_ml_preload_startup_floor(
                spec, tenant_id="acme"
            )

        # Spec untouched, no warning — even though startup_timeout is well
        # below the floor (caller's choice when preload is off).
        self.assertIs(result, spec)
        self.assertEqual(result.startup_timeout_seconds, 300)
        warnings = [r for r in captured.records if r.levelno >= logging.WARNING]
        self.assertEqual(warnings, [])

    def test_no_bump_when_ml_disabled(self) -> None:
        spec = _proxy_spec(
            env={"LLMTRACE_ML_ENABLED": "0", "LLMTRACE_ML_PRELOAD": "1"},
            startup_timeout_seconds=300,
        )
        with self.assertLogs(lifecycle.LOGGER, level=logging.DEBUG) as captured:
            lifecycle.LOGGER.debug("anchor")
            result = lifecycle._apply_ml_preload_startup_floor(
                spec, tenant_id="acme"
            )

        self.assertIs(result, spec)
        self.assertEqual(result.startup_timeout_seconds, 300)
        warnings = [r for r in captured.records if r.levelno >= logging.WARNING]
        self.assertEqual(warnings, [])

    def test_no_bump_when_both_flags_absent(self) -> None:
        spec = _proxy_spec(env={}, startup_timeout_seconds=120)
        with self.assertLogs(lifecycle.LOGGER, level=logging.DEBUG) as captured:
            lifecycle.LOGGER.debug("anchor")
            result = lifecycle._apply_ml_preload_startup_floor(
                spec, tenant_id="acme"
            )

        self.assertIs(result, spec)
        self.assertEqual(result.startup_timeout_seconds, 120)
        warnings = [r for r in captured.records if r.levelno >= logging.WARNING]
        self.assertEqual(warnings, [])

    def test_custom_floor_override(self) -> None:
        spec = _proxy_spec(
            env={"LLMTRACE_ML_ENABLED": "1", "LLMTRACE_ML_PRELOAD": "1"},
            startup_timeout_seconds=100,
        )
        with self.assertLogs(lifecycle.LOGGER, level=logging.WARNING):
            bumped = lifecycle._apply_ml_preload_startup_floor(
                spec, tenant_id="acme", floor=2400
            )

        self.assertEqual(bumped.startup_timeout_seconds, 2400)

    def test_truthy_variants_recognised(self) -> None:
        # Any value in the truthy set on BOTH flags triggers the bump.
        for value in ("1", "true", "TRUE", "True", "yes", "YES"):
            with self.subTest(value=value):
                spec = _proxy_spec(
                    env={
                        "LLMTRACE_ML_ENABLED": value,
                        "LLMTRACE_ML_PRELOAD": value,
                    },
                    startup_timeout_seconds=600,
                )
                bumped = lifecycle._apply_ml_preload_startup_floor(
                    spec, tenant_id="acme"
                )
                self.assertEqual(
                    bumped.startup_timeout_seconds,
                    lifecycle.ML_PRELOAD_STARTUP_FLOOR_SECONDS,
                )

    def test_falsy_variants_do_not_trigger(self) -> None:
        for value in ("0", "false", "no", "", "off", "FALSE"):
            with self.subTest(value=value):
                spec = _proxy_spec(
                    env={
                        "LLMTRACE_ML_ENABLED": "1",
                        "LLMTRACE_ML_PRELOAD": value,
                    },
                    startup_timeout_seconds=300,
                )
                result = lifecycle._apply_ml_preload_startup_floor(
                    spec, tenant_id="acme"
                )
                self.assertIs(result, spec)


if __name__ == "__main__":
    unittest.main()
