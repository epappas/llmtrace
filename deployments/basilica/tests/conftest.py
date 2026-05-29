"""Pytest config for the basilica lifecycle tests.

The library imports `basilica` (the upstream SDK) at module load. To keep
these unit tests dependency-free, we install a minimal stub into
`sys.modules` before any test imports the lifecycle module. Tests that
need to exercise SDK-driven code paths (e.g. `_create_component`) pass
in a fake client object directly, never going through the real SDK.
"""

from __future__ import annotations

import sys
import types
from typing import Any


def _install_basilica_stub() -> None:
    if "basilica" in sys.modules:
        return
    module = types.ModuleType("basilica")

    class _Stub:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.args = args
            self.kwargs = kwargs
            # Expose kwargs as attributes too, so tests that read the real
            # SDK's property accessors (e.g. StorageSpec.persistent,
            # PersistentStorageSpec.bucket) also work against the stub.
            for key, value in kwargs.items():
                setattr(self, key, value)

    module.BasilicaClient = _Stub
    module.HealthCheckConfig = _Stub
    module.ProbeConfig = _Stub

    # Storage SDK surface used by the persistent-volume path. Tests that
    # assert on the StorageSpec contents inspect these stubs' captured
    # kwargs/args (they never reach a real Basilica backend).
    module.PersistentStorageSpec = _Stub
    module.StorageSpec = _Stub

    class _StorageBackend:
        R2 = "R2"
        S3 = "S3"
        GCS = "GCS"

    module.StorageBackend = _StorageBackend
    sys.modules["basilica"] = module


_install_basilica_stub()
