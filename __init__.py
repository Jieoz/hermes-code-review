"""Hermes drop-in plugin registration."""

from __future__ import annotations

import sys
from pathlib import Path

_SOURCE = str(Path(__file__).resolve().parent / "src")
if _SOURCE not in sys.path:
    sys.path.insert(0, _SOURCE)

from hermes_code_review.plugin import register  # noqa: E402

__all__ = ["register"]
