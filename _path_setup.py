"""
_path_setup.py
--------------
Centralised path configuration for the Email Safety project.

The ``mcp-server/`` directory uses a hyphenated name that is not a valid
Python package identifier, so it cannot be imported via normal ``import``
statements.  This module adds the necessary directories to ``sys.path``
**once**, and every other module that needs cross-directory imports should
simply ``import _path_setup`` instead of doing its own ``sys.path`` hacking.

After running ``pip install -e .`` the ``agents`` package is importable
everywhere without any path manipulation.  This file only handles the
remaining ``mcp-server`` directory.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
MCP_SERVER_DIR = PROJECT_ROOT / "mcp-server"

_dirs_to_add = [
    str(PROJECT_ROOT),
    str(MCP_SERVER_DIR),
]

for _d in _dirs_to_add:
    if _d not in sys.path:
        sys.path.insert(0, _d)
