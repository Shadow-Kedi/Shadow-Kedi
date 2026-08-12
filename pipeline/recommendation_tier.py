# pipeline/recommendation_tier.py
"""
Maps risk_engine.py's statistical risk_category (Informational/Low/Medium/
High/Critical) onto the Recommendation Engine Logic Specification's R1-R6
action tiers (No action -> Escalate to security).

WHY THIS EXISTS

Your pipeline and the Recommendation Engine spec independently built two
different classification axes that were never reconciled:
  - risk_category answers "how anomalous is this" (statistical/ML)
  - R1-R6 answers "what should a human actually do about it" (ops/action)

Nothing upstream connects them. This module is that connection.

WHY risk_category (NOT raw risk_score) IS THE BASE INPUT

The spec's worked examples use literal risk_score cutoffs (30/60/85) to
pick a base tier. That is the exact "literal numeric threshold on a 0-100
score" approach risk_engine.py's own history already tested and rejected
twice -- once for the blueprint's original Low<=30/Medium<=60/High<=80/
Critical>80 cutoffs (flagged 40% of all days, 2.8% precision, unusable),
and again for a naive classifier-probability*100 scaling (compressed,
uncalibrated). risk_category is what those numbers became AFTER being
properly calibrated (percentile rank or absolute classifier-probability
thresholds, tuned per source). Re-deriving raw risk_score cutoffs here
would reintroduce a problem already fixed elsewhere in this pipeline.
This module instead maps the ALREADY-CALIBRATED tier onto R1-R6, and
layers the spec's other escalation inputs (repeat count, peer prevalence,
self-audit response) on top -- matching the worked examples' escalation
BEHAVIOR, not their literal score numbers, since those numbers assume a
different (uncalibrated) scale than what risk_category actually is.

ESCALATION LOGIC (priority order, per Section 4/5 of the spec)

1. self_audit_response == "denied" -> ALWAYS R6, regardless of everything
   else. Per the spec: "a denied action on a legitimate account is a
   stronger signal than the original anomaly itself" (worked example 5).
2. peer_prevalence >= threshold -> R4, regardless of base tier, EXCEPT
   Informational (never individually escalated -- see point 3) and
   Critical/R6 (already at the ceiling; a severe individual case
   shouldn't get downgraded just because it's ALSO widespread). Per
   worked example 3: a widespread pattern gets REDIRECTED to "evaluate
   for sanctioned alternative," not just escalated in severity -- a
   different kind of response, not a bigger version of the same one.
3. Otherwise: base tier from risk_category, escalated ONE step if
   repeat_count >= threshold (worked example 1 -> 2). Informational
   never escalates via repeat_count OR peer_prevalence alone -- per the
   spec, R1 is "below noise threshold, don't surface," and repeated or
   widespread noise is still noise; a genuine pattern of low-severity
   activity is Section 10's aggregate/organizational-level concern, not
   an individual per-alert escalation. (FIXED: an earlier version of
   this module applied the Informational exemption to repeat_count but
   NOT to peer_prevalence -- an Informational-tier event with 90% peer
   prevalence was getting redirected straight to R4, contradicting the
   module's own stated reasoning. Both escalation paths now exempt
   Informational consistently.)
4. is_known_bad_category (a Wazuh CDB-list content match, from Role 2)
   raises the tier to at least R5 if it's currently R1/R2/R3 -- a floor,
   never a downgrade. EXPLICITLY DOES NOT apply to R4: R4 means "this is
   widespread, treat it as an unmet business need, evaluate a sanctioned
   alternative" -- a different RESPONSE TYPE, not a severity level one
   notch below R5, even though R4 sits before R5 in TIER_ORDER. (FIXED:
   an earlier version let this floor silently override an R4 redirect
   whenever the domain was also on a CDB list. Concretely, per this
   project's own shadow-IT research report, Shadow AI is the category
   with the STRONGEST evidence for "provide a sanctioned alternative"
   over blocking [89%/54% reduction stats in 9-shadow-it-full-report.md
   9.6] -- but a widely-adopted AI tool would almost always also be on
   the ai_tool_domains CDB list, so the floor was silently overriding
   R4 with R5 [block] for exactly the category where blocking is the
   evidence-contradicted choice. R4 is now exempt from the floor, the
   same way R6 already was.)

THRESHOLDS ARE STARTING ESTIMATES, NOT EMPIRICALLY DERIVED

Per the spec's own Section 6: "the numeric cutoffs above... are starting
estimates, not empirically derived. This is exactly what the self-audit
accuracy feedback loop should tune over time." Defaults here match the
spec's stated starting points (repeat_count >= 3, peer_prevalence >= 40%)
-- tune both once real self-audit outcome data exists.

INPUT VALIDATION

recommend_tier() raises ValueError on an unrecognized risk_category, an
out-of-range peer_prevalence (must be 0.0-1.0), a negative repeat_count,
or a self_audit_response outside {None, "confirmed", "denied"}. This is
deliberately fail-fast rather than silently coercing bad input -- a
security-relevant recommendation tier is the wrong place for a silently
wrong default to hide.

FORWARD-COMPATIBLE BATCH APPLICATION

apply_recommendation_tiers(df) is the DataFrame-native entry point for
risk_scores.csv-shaped data. It reads repeat_count/peer_prevalence/
self_audit_response/is_known_bad_category from the DataFrame if those
columns exist, and falls back to recommend_tier()'s own defaults (with a
one-time printed note) for whichever don't -- today, that's all four,
since none of those upstream signals exist in the pipeline yet. The
point: the moment Role 1/Role 2 wire up real repeat-count tracking,
peer-prevalence computation, self-audit responses, or CDB-list match
flags as real columns, this function starts using them automatically.
No caller-side rewrite needed when that day comes.

Usage:
    from pipeline.recommendation_tier import recommend_tier, apply_recommendation_tiers

    result = recommend_tier(risk_category="High", repeat_count=4)
    # -> {"tier": "R3", "label": "Flag for IT review", "reasoning": [...], "explanation": "..."}

    import pandas as pd
    daily = pd.read_csv("data/processed/risk_scores.csv")
    daily = apply_recommendation_tiers(daily)
    daily.to_csv("data/processed/risk_scores_with_r_tier.csv", index=False)
"""

from dataclasses import dataclass, field

import pandas as pd

# Base tier when none of the escalation rules fire. Chosen to match the
# spec's own description of each R-tier's intent (Section 3) against what
# each risk_category tier actually represents in THIS pipeline (see
# risk_categorization.py's docstring for what Informational/Low/etc. mean
# here specifically) -- a judgment call, since the two systems use
# different underlying scales, not a precise algebraic conversion.
BASE_TIER_BY_CATEGORY = {
    "Informational": "R1",
    "Low": "R1",
    "Medium": "R2",   # validated directly against worked example 1: score=45 (spec's 30-60 band) -> R2
    "High": "R3",     # spec's 60-85 band
    "Critical": "R6", # validated directly against worked example 4: score=92 (spec's >85 band) -> R6
}

TIER_LABELS = {
    "R1": "No action / log only",
    "R2": "Notify employee (educate)",
    "R3": "Flag for IT review",
    "R4": "Recommend sanctioned-alternative evaluation",
    "R5": "Recommend block/restrict",
    "R6": "Escalate to security (critical)",
}

TIER_ORDER = ["R1", "R2", "R3", "R4", "R5", "R6"]

VALID_SELF_AUDIT_RESPONSES = (None, "confirmed", "denied")

# Tiers the known-bad-category floor is allowed to raise FROM. Deliberately
# excludes R4 (a redirect to a different response type, not a severity
# level -- see module docstring point 4) and R5/R6 (already at or above
# the floor, nothing to raise).
FLOOR_APPLIES_FROM = ("R1", "R2", "R3")


@dataclass
class TierResult:
    tier: str
    label: str
    reasoning: list = field(default_factory=list)

    def as_dict(self):
        return {
            "tier": self.tier,
            "label": self.label,
            "reasoning": self.reasoning,
            "explanation": " ".join(self.reasoning),
        }


def _escalate_one_step(tier: str) -> str:
    idx = TIER_ORDER.index(tier)
    return TIER_ORDER[min(idx + 1, len(TIER_ORDER) - 1)]


def recommend_tier(risk_category: str, repeat_count: int = 1, peer_prevalence: float = 0.0,
                    self_audit_response: str = None, is_known_bad_category: bool = False,
                    repeat_threshold: int = 3, peer_prevalence_threshold: float = 0.40) -> dict:
    """
    risk_category: one of Informational/Low/Medium/High/Critical (from
        risk_engine.py's risk_scores.csv, `risk_category` column)
    repeat_count: number of times this same alert type has fired for this
        user (matches the spec's own repeat_count concept, worked examples 1-2)
    peer_prevalence: fraction (0.0-1.0) of the peer group also flagged for
        the same category (worked example 3 uses 0.43)
    self_audit_response: None / "confirmed" / "denied" -- None means no
        self-audit has happened yet for this alert
    is_known_bad_category: True if the event matched one of Role 2's Wazuh
        CDB lists (shadow_it_domains, ai_tool_domains, cloud_sync_domains,
        unapproved_software) -- a content-based signal, not a statistical
        one. Applied as a FLOOR to R1/R2/R3 only -- see module docstring
        point 4 for why R4 is explicitly exempt.

    Raises ValueError on any out-of-range/unrecognized input -- fail-fast
    rather than silently defaulting on bad data.
    """
    if risk_category not in BASE_TIER_BY_CATEGORY:
        raise ValueError(f"Unknown risk_category: {risk_category!r}. "
                          f"Expected one of {list(BASE_TIER_BY_CATEGORY)}")
    if self_audit_response not in VALID_SELF_AUDIT_RESPONSES:
        raise ValueError(f"self_audit_response must be one of {VALID_SELF_AUDIT_RESPONSES}, "
                          f"got {self_audit_response!r}")
    if not 0.0 <= peer_prevalence <= 1.0:
        raise ValueError(f"peer_prevalence must be between 0.0 and 1.0, got {peer_prevalence!r}")
    if repeat_count < 0:
        raise ValueError(f"repeat_count must be >= 0, got {repeat_count!r}")

    reasoning = []

    # Rule 1: self-audit denial always wins (spec worked example 5)
    if self_audit_response == "denied":
        reasoning.append("self_audit_response='denied' on a legitimate account is treated as a "
                          "stronger signal than the original anomaly -- forced to R6 regardless of base tier.")
        return TierResult("R6", TIER_LABELS["R6"], reasoning).as_dict()

    base_tier = BASE_TIER_BY_CATEGORY[risk_category]
    tier = base_tier
    reasoning.append(f"risk_category='{risk_category}' -> base tier {base_tier} ({TIER_LABELS[base_tier]}).")

    # Rule 2: peer prevalence redirects to R4 (spec worked example 3) --
    # exempt for Informational (never individually escalated, same
    # reasoning as its repeat_count exemption below) and for an already-
    # Critical/R6 base tier (a severe individual case isn't downgraded
    # just because it's ALSO widespread).
    if (risk_category != "Informational" and peer_prevalence >= peer_prevalence_threshold
            and base_tier != "R6"):
        tier = "R4"
        reasoning.append(f"peer_prevalence={peer_prevalence:.0%} >= {peer_prevalence_threshold:.0%} threshold -- "
                          f"redirected to R4 (widespread pattern suggests unmet business need, "
                          f"not individual risk, per spec worked example 3).")
    elif risk_category != "Informational" and repeat_count >= repeat_threshold:
        # Rule 3: escalate one step on repeat (spec worked examples 1->2).
        # Informational is exempt here too -- see module docstring point 3.
        tier = _escalate_one_step(base_tier)
        reasoning.append(f"repeat_count={repeat_count} >= {repeat_threshold} threshold -- "
                          f"escalated one step: {base_tier} -> {tier}.")

    # Rule 4: known-bad-category floor (content-based signal from Role 2's
    # Wazuh CDB lists) -- raises R1/R2/R3 to at least R5. Explicitly does
    # NOT apply to R4 (a response-type redirect, not a severity level --
    # see module docstring point 4) or R5/R6 (already at/above the floor).
    if is_known_bad_category and tier in FLOOR_APPLIES_FROM:
        reasoning.append(f"is_known_bad_category=True (matched a Wazuh CDB list) -- "
                          f"raised floor from {tier} to R5 regardless of statistical tier.")
        tier = "R5"

    return TierResult(tier, TIER_LABELS[tier], reasoning).as_dict()


def apply_recommendation_tiers(df: pd.DataFrame, repeat_threshold: int = 3,
                                peer_prevalence_threshold: float = 0.40) -> pd.DataFrame:
    """
    Batch-applies recommend_tier() over a risk_scores.csv-shaped
    DataFrame. Adds r_tier, r_tier_label, and r_tier_explanation columns.
    Reads repeat_count/peer_prevalence/self_audit_response/
    is_known_bad_category from df if those columns exist; falls back to
    recommend_tier()'s own defaults (printing a one-time note about which
    ones aren't available yet) otherwise -- see module docstring for why
    this makes the function forward-compatible with no caller-side
    rewrite needed once those upstream signals exist for real.
    """
    optional_cols = {
        "repeat_count": 1,
        "peer_prevalence": 0.0,
        "self_audit_response": None,
        "is_known_bad_category": False,
    }
    missing = [c for c in optional_cols if c not in df.columns]
    if missing:
        print(f"NOTE (recommendation_tier): column(s) not yet available upstream, "
              f"using defaults for now: {missing}")

    def _row_tier(row):
        kwargs = {col: (row[col] if col in df.columns else default)
                  for col, default in optional_cols.items()}
        return recommend_tier(risk_category=row["risk_category"], repeat_threshold=repeat_threshold,
                               peer_prevalence_threshold=peer_prevalence_threshold, **kwargs)

    results = df.apply(_row_tier, axis=1)
    out = df.copy()
    out["r_tier"] = results.apply(lambda r: r["tier"])
    out["r_tier_label"] = results.apply(lambda r: r["label"])
    out["r_tier_explanation"] = results.apply(lambda r: r["explanation"])
    return out


if __name__ == "__main__":
    # Sanity-check against the spec's own worked examples (Section 5),
    # plus regression tests for the two bugs fixed above -- these stay
    # here as a permanent guard against reintroducing either one.
    print("--- Worked example 1: score=45 (30-60 band -> Medium), first occurrence ---")
    print(recommend_tier(risk_category="Medium", repeat_count=1))

    print("\n--- Worked example 2: same case, 4th repeat ---")
    print(recommend_tier(risk_category="Medium", repeat_count=4))

    print("\n--- Worked example 3: score=70 (60-85 band -> High), widespread across peer group ---")
    print(recommend_tier(risk_category="High", repeat_count=1, peer_prevalence=0.43))

    print("\n--- Worked example 4: score=92 (>85 band -> Critical), severe individual anomaly ---")
    print(recommend_tier(risk_category="Critical", repeat_count=1))

    print("\n--- Worked example 5: self-audit denial overrides everything ---")
    print(recommend_tier(risk_category="Medium", repeat_count=1, self_audit_response="denied"))

    print("\n--- Regression: Informational does NOT escalate via repeat alone ---")
    print(recommend_tier(risk_category="Informational", repeat_count=10))

    print("\n--- Regression (FIXED BUG): Informational does NOT escalate via peer_prevalence either ---")
    print(recommend_tier(risk_category="Informational", repeat_count=1, peer_prevalence=0.9))

    print("\n--- Regression: known-bad-category floor reaches R5 from R1/R2/R3 ---")
    print(recommend_tier(risk_category="High", repeat_count=1, is_known_bad_category=True))

    print("\n--- Regression (FIXED BUG): known-bad-category floor does NOT override an R4 redirect ---")
    print(recommend_tier(risk_category="High", repeat_count=1, peer_prevalence=0.5, is_known_bad_category=True))

    print("\n--- Regression: known-bad-category floor never downgrades an R6 self-audit denial ---")
    print(recommend_tier(risk_category="Medium", self_audit_response="denied", is_known_bad_category=True))
