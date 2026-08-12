# pipeline/risk_categorization.py
"""
Shared 5-tier risk categorization logic.

Replaces the 4-tier Low/Medium/High/Critical scheme with a 5-tier scheme,
adding a bottom "Informational" tier below Low. Written as a standalone
module rather than inlined in risk_engine.py because the project has TWO
categorization paths that both need this: the percentile-rank mode
(heuristic-only fallback) and the classifier-probability absolute-
threshold mode (with per-source overrides, e.g. --casb-high). Both should
categorize the same way conceptually (5 ordered tiers, boundary values
increasing) -- this module is the one place that logic lives so the two
paths can't drift apart.

WHY "INFORMATIONAL" AS THE NEW 5TH TIER (not e.g. splitting Critical into two):
The existing Low/Medium/High/Critical boundaries were deliberately tuned
around SOC triage capacity (a human analyst can investigate the top 1-5% of
days, not more) -- per risk_engine.py's own comments, "Low" is genuinely
just "everything else," which on real data is the vast majority of
user-days. Splitting that undifferentiated bulk into "Informational" (truly
nothing notable) and "Low" (mildly elevated, worth a glance in aggregate
trend views even if not worth an individual alert) adds real triage value.
Splitting Critical further would not -- the top 1% is already the smallest,
most-scrutinized tier, and subdividing it further fights the SOC-capacity
reasoning the thresholds were built around in the first place.

Default tier names follow a standard, widely-recognized 5-level severity
convention (Informational/Low/Medium/High/Critical, the same shape used by
CVSS-adjacent SOC tooling generally) -- pass a custom `labels` tuple to
rename them if your dashboard/checklist uses different terms.
"""

from dataclasses import dataclass
from typing import Sequence

DEFAULT_LABELS = ("Informational", "Low", "Medium", "High", "Critical")


@dataclass(frozen=True)
class TierBoundaries:
    """Four ascending cutoffs defining five tiers:
    [ -inf, low ) -> labels[0]
    [ low, medium ) -> labels[1]
    [ medium, high ) -> labels[2]
    [ high, critical ) -> labels[3]
    [ critical, +inf ) -> labels[4]
    """
    low: float
    medium: float
    high: float
    critical: float

    def __post_init__(self):
        if not (self.low < self.medium < self.high < self.critical):
            raise ValueError(
                f"Tier boundaries must be strictly ascending: "
                f"low={self.low} < medium={self.medium} < high={self.high} < critical={self.critical}"
            )


def categorize(value: float, boundaries: TierBoundaries, labels: Sequence[str] = DEFAULT_LABELS) -> str:
    """Maps a single numeric value onto one of 5 ordered tier labels.
    Works identically whether `value` is a 0-100 percentile score or a
    0-1 classifier probability -- the caller picks boundaries matching
    whichever scale they're using (see the two presets below)."""
    if len(labels) != 5:
        raise ValueError(f"Exactly 5 labels required, got {len(labels)}: {labels}")
    if value >= boundaries.critical:
        return labels[4]
    elif value >= boundaries.high:
        return labels[3]
    elif value >= boundaries.medium:
        return labels[2]
    elif value >= boundaries.low:
        return labels[1]
    else:
        return labels[0]


# ----------------------------------------------------------------------
# Preset 1: percentile-rank mode (risk_engine.py's --medium-pct etc. args,
# extended with a new --low-pct)
# ----------------------------------------------------------------------

def percentile_boundaries(low_pct: float = 70.0, medium_pct: float = 90.0,
                           high_pct: float = 97.0, critical_pct: float = 99.0) -> TierBoundaries:
    """Defaults preserve the existing Medium/High/Critical cutoffs exactly
    (90th/97th/99th percentile, i.e. top 10%/3%/1%) and add Low at the 70th
    percentile -- so the bottom 70% of days is Informational, the next 20%
    (70th-90th) is Low, and Medium/High/Critical are unchanged from before."""
    return TierBoundaries(low=low_pct, medium=medium_pct, high=high_pct, critical=critical_pct)


# ----------------------------------------------------------------------
# Preset 2: classifier-probability absolute-threshold mode (the project's
# locked-in mode: --classifier-high/-critical, with per-source overrides
# like --casb-high/--casb-critical)
# ----------------------------------------------------------------------

def classifier_boundaries(low: float = 0.02, medium: float = 0.10,
                           high: float = 0.50, critical: float = 0.90) -> TierBoundaries:
    """Defaults match the project's pre-sweep starting point (Medium>=0.10,
    High>=0.50, Critical>=0.90). Low=0.02 is new -- pick it the same way
    the other tiers were tuned: run the threshold sweep, look at the
    probability distribution just above the noise floor, and set
    --classifier-low there rather than trusting this default blindly.
    These numbers are data-dependent, not universal."""
    return TierBoundaries(low=low, medium=medium, high=high, critical=critical)
