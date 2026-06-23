"""Pytest bootstrap shared by the whole suite.

The historical test module (``tests/testPProxy.py``) imports the engine as
``privacy_proxy`` while the implementation lives in ``pProxy.py``. Register an
in-process alias so ``from privacy_proxy import ...`` resolves to the same module
object, matching the contract documented in ``pytest.ini`` (which lists
``privacy_proxy`` among the importable top-level modules).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import pProxy  # noqa: E402

sys.modules.setdefault("privacy_proxy", pProxy)
