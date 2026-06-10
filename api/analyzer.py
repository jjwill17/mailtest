from __future__ import annotations

from typing import Any, Dict

from analyzer_core.pipeline import analyze_message as _analyze_message


def analyze_message(raw_message: str, raw_message_b64: str | None = None) -> Dict[str, Any]:
    """Compatibility wrapper for the new modular analyzer pipeline."""
    return _analyze_message(raw_message, raw_message_b64)
