"""Unit tests for the replica/metadata-profile warning.

`_warn_on_unsharable_replicas` is a pure function on `ComponentSpec`; the
tests exercise it directly via the real `LOGGER`, captured with the
standard `unittest.TestCase.assertLogs` context manager (the test-suite
convention here — see `test_ml_preload_startup_floor.py`). No mocking of
`LOGGER.warning` — the production logger emits the real record.
"""

from __future__ import annotations

import logging
import unittest
from typing import Mapping

from deployments.basilica import lifecycle


def _proxy_spec(
    *, env: Mapping[str, str], replicas: int
) -> lifecycle.ComponentSpec:
    return lifecycle.ComponentSpec(
        image="ghcr.io/techlab-innov/llmtrace-proxy:latest",
        port=8080,
        cpu="2",
        memory="4Gi",
        replicas=replicas,
        env=env,
    )


class ReplicaMetadataWarningTests(unittest.TestCase):
    def test_no_warning_when_single_replica(self) -> None:
        spec = _proxy_spec(
            env={"LLMTRACE_STORAGE_PROFILE": "sqlite"}, replicas=1
        )
        with self.assertLogs(lifecycle.LOGGER, level=logging.DEBUG) as captured:
            lifecycle.LOGGER.debug("anchor")
            lifecycle._warn_on_unsharable_replicas(spec, "acme")

        warnings = [r for r in captured.records if r.levelno >= logging.WARNING]
        self.assertEqual(warnings, [])

    def test_warning_emitted_for_replicas_two_with_sqlite(self) -> None:
        spec = _proxy_spec(
            env={"LLMTRACE_STORAGE_PROFILE": "sqlite"}, replicas=2
        )
        with self.assertLogs(lifecycle.LOGGER, level=logging.WARNING) as captured:
            lifecycle._warn_on_unsharable_replicas(spec, "acme")

        self.assertEqual(len(captured.records), 1)
        record = captured.records[0]
        self.assertEqual(record.levelno, logging.WARNING)
        message = record.getMessage()
        self.assertIn("acme", message)
        self.assertIn("replicas=2", message)
        self.assertIn("sqlite", message)
        self.assertIn("postgres", message)
        self.assertIn("diverge", message)

    def test_no_warning_when_replicas_two_with_postgres(self) -> None:
        spec = _proxy_spec(
            env={"LLMTRACE_STORAGE_PROFILE": "postgres"}, replicas=2
        )
        with self.assertLogs(lifecycle.LOGGER, level=logging.DEBUG) as captured:
            lifecycle.LOGGER.debug("anchor")
            lifecycle._warn_on_unsharable_replicas(spec, "acme")

        warnings = [r for r in captured.records if r.levelno >= logging.WARNING]
        self.assertEqual(warnings, [])

    def test_warning_when_profile_missing_falls_back_to_sqlite_default(
        self,
    ) -> None:
        # Empty / missing profile resolves to sqlite at the proxy. The
        # message must surface that explicitly so the operator knows
        # what's happening.
        spec = _proxy_spec(env={}, replicas=3)
        with self.assertLogs(lifecycle.LOGGER, level=logging.WARNING) as captured:
            lifecycle._warn_on_unsharable_replicas(spec, "acme")

        self.assertEqual(len(captured.records), 1)
        message = captured.records[0].getMessage()
        self.assertIn("sqlite (default)", message)
        self.assertIn("replicas=3", message)

    def test_warning_recognises_lite_and_memory_profiles(self) -> None:
        for profile in ("lite", "memory", "SQLITE", "Memory"):
            with self.subTest(profile=profile):
                spec = _proxy_spec(
                    env={"LLMTRACE_STORAGE_PROFILE": profile}, replicas=2
                )
                with self.assertLogs(
                    lifecycle.LOGGER, level=logging.WARNING
                ) as captured:
                    lifecycle._warn_on_unsharable_replicas(spec, "acme")

                self.assertEqual(len(captured.records), 1)


if __name__ == "__main__":
    unittest.main()
