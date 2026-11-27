"""Numeric settings from the environment. A bad value never crashes startup: the default is used and one line says so."""
from __future__ import annotations

import os
import sys


def env_num(name: str, default: float, lo: float = 1, hi: float | None = None, cast=int):
    """Read ``name`` as a number in [lo, hi]. On a missing, unparsable or out-of-range value use ``default`` and
    (only when a value was set) warn once on stderr. The value itself is not echoed, it may be sensitive."""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return cast(default)
    try:
        v = cast(raw.strip())
        if v != v or v < lo or (hi is not None and v > hi):    # v != v catches NaN
            raise ValueError
        return v
    except (ValueError, OverflowError):
        print(f"warning: {name} is not a valid number in [{lo}, {hi if hi is not None else 'no max'}]; using the default {default}",
              file=sys.stderr, flush=True)
        return cast(default)
