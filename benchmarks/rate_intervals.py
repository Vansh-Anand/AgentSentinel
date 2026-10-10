"""Descriptive binomial intervals for single-trial, fixed-corpus reports."""

from __future__ import annotations

import math


def wilson_95(successes: int, total: int) -> tuple[float, float] | None:
    """Return a 95% Wilson score interval as fractions, or None for no trials.

    The interval describes repeated Bernoulli sampling under its assumptions.
    It does not make a curated prompt-injection corpus representative of all
    real-world attacks, and repeated trials of one case are not independent.
    """
    if not isinstance(successes, int) or not isinstance(total, int) or total < 0 \
            or not 0 <= successes <= total:
        raise ValueError("invalid rate counts")
    if total == 0:
        return None
    z = 1.959963984540054
    p = successes / total
    denominator = 1 + z * z / total
    midpoint = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return max(0.0, midpoint - margin), min(1.0, midpoint + margin)
