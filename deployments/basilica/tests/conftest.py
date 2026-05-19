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

    module.BasilicaClient = _Stub
    module.HealthCheckConfig = _Stub
    module.ProbeConfig = _Stub
    sys.modules["basilica"] = module


_install_basilica_stub()
