"""Shared secret-detection utilities (Shannon entropy gate, tuned
threshold 2.8 from v1 false-positive work). Any language plugin can
reuse these instead of re-deriving thresholds."""
from __future__ import annotations

import re

from guardian.scanner._engine import ENTROPY_THRESHOLD, shannon_entropy  # re-export

__all__ = ["shannon_entropy", "ENTROPY_THRESHOLD", "entropy_gate"]


def entropy_gate(var_name: str, value: str) -> bool:
    """True if the candidate value looks like a real secret rather than
    a constant-name-equals-value label or low-entropy placeholder."""
    normalized_name = re.sub(r'[_\W]', '', var_name).lower()
    normalized_value = re.sub(r'[_\W]', '', value).lower()
    if normalized_value == normalized_name:
        return False
    if shannon_entropy(value) < ENTROPY_THRESHOLD and not re.search(r'\d', value):
        return False
    return True
