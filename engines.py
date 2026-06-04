"""
HB-Eval OS — Reliability Computation Engine
============================================
Implements the five reliability metrics exactly as defined in the paper
(submitted June 2, 2026). All formula references are to the paper's
equation numbers so a reviewer can cross-check each calculation.

Important: this module is intentionally stateless. It receives a payload
dict and returns a metrics dict. All I/O (Supabase reads/writes, Redis,
HTTP) happens in gateway.py — never here. This separation makes the
computation testable in isolation with no infrastructure.
"""

import math
import statistics
from typing import Any

# ──────────────────────────────────────────────────────────────────────────────
# Tier thresholds (Table 1 of the paper).
# These constants are the single source of truth used by both the engine
# and the certification logic. Changing them here changes behavior everywhere.
# ──────────────────────────────────────────────────────────────────────────────
TIER_THRESHOLDS = {
    1: {"pei": 0.70, "irs": 0.60, "frr": 0.70, "ti": 3.0, "csi": 0.70},
    2: {"pei": 0.80, "irs": 0.75, "frr": 0.85, "ti": 4.0, "csi": 0.80},
    3: {"pei": 0.90, "irs": 0.90, "frr": 0.95, "ti": 4.5, "csi": 0.90},
}

# γ = 0.20: per-violation quality penalty (Equation 5, paper Section 3.3).
# Derived from expert calibration: each constraint violation corresponds to
# a 20% reduction in operational quality (median rating from calibration corpus).
PEI_VIOLATION_WEIGHT: float = 0.20

# c = 0.5: CSI normalisation constant (Equation 9, paper Section 3.6).
# Maps maximum observable instability (σ = 0.25) to a complete stability penalty.
CSI_NORMALISATION_C: float = 0.5

# Window sizes for CSI computation (paper Section 3.6).
CSI_WINDOW_N: int = 100   # Standard deviation window
CSI_TREND_M: int = 20     # Failure trend OLS window


class HBEvalEngines:
    """
    Stateless computation engine for HB-Eval OS reliability metrics.

    Every public method is a pure function: given the same inputs it
    always returns the same output. There are no side effects, no global
    state mutations, and no I/O. This makes every method independently
    unit-testable.
    """

    # ──────────────────────────────────────────────────────────────────────
    # Metric 1 — FRR: Failure Resilience Rate (Equation 4)
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def score_recovery_episode(episode: dict[str, Any]) -> float:
        """
        Assigns a quality score to a single recovery episode using the
        four-level rubric from Equation 4 of the paper.

        The rubric was calibrated on a 200-episode corpus (Cohen's κ = 0.76,
        95% CI [0.72, 0.80]). The four levels are deliberately discrete
        rather than continuous, which is what gives FRR its inter-rater
        reliability.

        episode must contain:
            steps_to_recovery  int   — steps taken after fault onset
            approach_correct   bool  — whether the recovery approach was sound
            recovered          bool  — whether the task eventually succeeded
        """
        recovered = episode.get("recovered", False)
        if not recovered:
            return 0.0  # No recovery; task fails → q = 0.0

        steps = episode.get("steps_to_recovery", 999)
        correct = episode.get("approach_correct", False)

        if steps <= 2 and correct:
            return 1.0   # Recovery within 2 steps, correct approach
        elif steps <= 5:
            return 0.7   # Recovery within 5 steps, minor deviations
        else:
            return 0.4   # Eventual recovery via repeated attempts

    @staticmethod
    def calculate_frr(episodes: list[dict[str, Any]]) -> float:
        """
        Computes FRR as the expected value of q() over all fault encounters.
        Returns 1.0 (perfect resilience) when there are no fault episodes,
        because the absence of faults means no failures to recover from.

        FRR(π) = E_{t,f}[q(E(t,f,π))]   (Equation 4)
        """
        if not episodes:
            return 1.0

        scores = [HBEvalEngines.score_recovery_episode(ep) for ep in episodes]
        return sum(scores) / len(scores)

    # ──────────────────────────────────────────────────────────────────────
    # Metric 2 — PEI: Planning Efficiency Index (Equation 5)
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def calculate_pei(l_min: int, l_actual: int, violations: int) -> float:
        """
        Computes PEI for a single run.

        PEI(π) = E_{t,f}[ (L_min^oracle / L_actual) · QF(t,f,π) ]
                                                        (Equation 5)
        QF     = max(0, 1 − γ · v)    where γ = 0.20

        PEI ∈ [0, 1] with equality iff L_actual = L_min and v = 0.
        Values above 1.0 are mathematically impossible: L_actual < L_min
        would mean the agent took fewer steps than the oracle minimum,
        which the oracle definition prevents by construction.

        Args:
            l_min       Oracle-verified minimum step count for this task.
            l_actual    Actual step count: len(payload["trajectory"]).
            violations  Count of hard constraint violations: payload["constraint_violations"].
        """
        # Guard against malformed payloads where l_actual could be 0.
        if l_actual <= 0:
            return 0.0

        efficiency_ratio = min(1.0, l_min / l_actual)   # ≤ 1 by definition
        quality_factor   = max(0.0, 1.0 - PEI_VIOLATION_WEIGHT * violations)
        return round(efficiency_ratio * quality_factor, 4)

    # ──────────────────────────────────────────────────────────────────────
    # Metric 3 — IRS: Intentional Recovery Score (Equation 6)
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def classify_recovery_intentionality(episode: dict[str, Any]) -> int:
        """
        Returns 1 if a recovery episode satisfies all three intentionality
        conditions (C1, C2, C3), and 0 otherwise.

        C1 — Memory query within k ≤ 3 steps of fault onset.
        C2 — Retrieved episode similarity ≥ τ_sim = 0.87.
        C3 — Subsequent action incorporates a verifiable modification.

        The gateway does not compute cosine similarity itself (that is the
        EDM's responsibility). Instead, the payload carries a boolean
        field `memory_similarity_met` that the EDM sets before passing
        the episode to the engine. If this field is absent, the engine
        conservatively assumes C2 is not met.

        episode must contain:
            memory_query_step      int   — step at which memory was queried
            fault_onset_step       int   — step at which the fault occurred
            memory_similarity_met  bool  — C2 result from EDM
            modification_verified  bool  — C3 result from trace analysis
        """
        fault_onset = episode.get("fault_onset_step", 0)
        query_step  = episode.get("memory_query_step", None)

        # C1: memory must have been queried, and within 3 steps of fault onset
        if query_step is None:
            return 0
        if (query_step - fault_onset) > 3:
            return 0

        # C2: similarity threshold (set by EDM, reported as boolean here)
        if not episode.get("memory_similarity_met", False):
            return 0

        # C3: explicit modification verified in the execution trace
        if not episode.get("modification_verified", False):
            return 0

        return 1

    @staticmethod
    def calculate_irs(recovery_episodes: list[dict[str, Any]]) -> float:
        """
        IRS(π) = (1/|R|) · Σ_{e∈R} 1_int(e)    (Equation 6)

        IRS is defined only over fault-perturbed successful recovery
        episodes (R). Returns None when R is empty, because IRS is
        undefined for nominal (fault-free) runs. The gateway maps
        None to the string "N/A" in the response.

        τ_sim = 0.87 was calibrated on a 150-episode annotation set:
        F1 maximised at 87.3% precision, 76.8% recall.
        """
        if not recovery_episodes:
            # IRS is undefined for runs with no fault encounters.
            return None

        intentional = sum(
            HBEvalEngines.classify_recovery_intentionality(ep)
            for ep in recovery_episodes
        )
        return round(intentional / len(recovery_episodes), 4)

    # ──────────────────────────────────────────────────────────────────────
    # Metric 4 — TI: Traceability Index (Equation 7)
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def calculate_ti(llm_judge_score: float | None) -> float | None:
        """
        TI(π) = E_{t,f}[J_φ(E(t,f,π))]     (Equation 7)

        J_φ is GPT-4o operating as a calibrated judge on the 1–5 Likert
        scale. The judge call is made outside this engine (in gateway.py)
        because it requires network I/O. This method validates the returned
        score and ensures it falls within the defined range.

        Calibration stats: Pearson r = 0.89, κ = 0.82, MAE = 0.43 points.

        Returns None when the judge call was skipped (e.g., development
        mode or API outage). The gateway maps None to "unavailable" in
        the response and excludes TI from tier computation.
        """
        if llm_judge_score is None:
            return None

        # Clamp to [1.0, 5.0] to handle any judge miscalibration at boundaries.
        return round(max(1.0, min(5.0, float(llm_judge_score))), 2)

    # ──────────────────────────────────────────────────────────────────────
    # Metric 5 — CSI: Consistency Stability Index (Equations 7, 8, 9)
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def calculate_sigma(scores: list[float]) -> float:
        """
        Sample standard deviation over a window of N metric scores.
        Equation 7: σ = sqrt( 1/(N-1) · Σ(x_i - x̄)² )
        Returns 0.0 for a single-element window (no variance possible).
        """
        if len(scores) < 2:
            return 0.0
        return statistics.stdev(scores)

    @staticmethod
    def calculate_rho_fail(outcome_sequence: list[bool]) -> float:
        """
        Normalised OLS slope of the failure rate over the M = 20 most
        recent runs (Equation 8).

        F_i = 1 − ω_i ∈ {0, 1} (failure indicator for run i).
        The OLS slope β̂ is normalised and clipped to [0, 1]:

            ρ_fail = clip( β̂_OLS / max(|β̂_OLS|, ε), 0, 1 )
            ε = 10⁻⁶

        A positive ρ_fail means failures are increasing over time.
        A negative slope is clipped to 0 (stable or improving is treated
        the same for the stability penalty).

        outcome_sequence is a list of booleans (True = success, False = failure)
        in chronological order (oldest first).
        """
        m_window = outcome_sequence[-CSI_TREND_M:]  # use last M runs
        n = len(m_window)

        if n < 2:
            return 0.0  # not enough data to estimate a trend

        # Failure indicators: F_i = 1 if failed, 0 if succeeded
        failures = [0.0 if outcome else 1.0 for outcome in m_window]

        # OLS slope: β̂ = Σ(x_i - x̄)(y_i - ȳ) / Σ(x_i - x̄)²
        x_vals = list(range(n))
        x_mean = sum(x_vals) / n
        y_mean = sum(failures) / n

        numerator   = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_vals, failures))
        denominator = sum((x - x_mean) ** 2 for x in x_vals)

        if denominator == 0:
            return 0.0

        beta_ols = numerator / denominator

        # Normalise and clip to [0, 1] — negative slopes (improving trend) become 0
        epsilon = 1e-6
        rho = beta_ols / max(abs(beta_ols), epsilon)
        return max(0.0, min(1.0, rho))

    @staticmethod
    def calculate_csi(
        pei_history: list[float],
        irs_history: list[float],
        outcome_history: list[bool],
    ) -> float | None:
        """
        CSI_N = (1 − min(1, 2σ_PEI/c)) × (1 − min(1, 2σ_IRS/c)) × (1 − ρ_fail)
                                                                   (Equation 9)

        Requires at least 2 historical runs to compute σ (otherwise undefined).
        Returns None when history is insufficient.

        CSI ∈ [0, 1].
        CSI = 1 iff σ_PEI = σ_IRS = 0 and ρ_fail = 0 (perfect stability).
        CSI = 0 if any factor reaches its minimum (maximum instability in
              any dimension collapses the index to zero).

        Note: CSI thresholds are provisional (paper Section 12.6).
        c = 0.5 is theoretically motivated but not yet empirically calibrated
        against production data across thousands of episodes.
        """
        n = min(len(pei_history), len(irs_history), len(outcome_history))
        if n < 2:
            return None  # not enough history to compute variance

        pei_window = pei_history[-CSI_WINDOW_N:]
        irs_window = irs_history[-CSI_WINDOW_N:]

        sigma_pei = HBEvalEngines.calculate_sigma(pei_window)
        sigma_irs = HBEvalEngines.calculate_sigma(irs_window)
        rho_fail  = HBEvalEngines.calculate_rho_fail(outcome_history)

        c = CSI_NORMALISATION_C
        pei_stability = 1.0 - min(1.0, (2 * sigma_pei) / c)
        irs_stability = 1.0 - min(1.0, (2 * sigma_irs) / c)
        trend_penalty = 1.0 - rho_fail

        return round(pei_stability * irs_stability * trend_penalty, 4)

    # ──────────────────────────────────────────────────────────────────────
    # Tier assignment — weakest-link rule (Table 1 of the paper)
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def assign_tier(metrics: dict[str, float | None]) -> int | None:
        """
        Returns the highest tier for which all five metric thresholds are
        simultaneously satisfied, or None if no tier is achieved.

        The weakest-link rule: an agent that achieves Tier 3 on four metrics
        but Tier 1 on IRS receives Tier 1 — because its intentional recovery
        is insufficient for higher-trust deployment regardless of efficiency.

        Metrics whose value is None (TI or CSI when history is insufficient)
        are excluded from tier computation for that run. This is intentional:
        we do not penalise an agent for missing data, but we also cannot
        certify on incomplete information.
        """
        for tier in [3, 2, 1]:  # check highest first
            thresholds = TIER_THRESHOLDS[tier]
            all_met = True
            for metric_name, threshold in thresholds.items():
                value = metrics.get(metric_name)
                if value is None:
                    continue  # skip metrics with insufficient data
                if value < threshold:
                    all_met = False
                    break
            if all_met:
                return tier

        return None  # no tier achieved

    # ──────────────────────────────────────────────────────────────────────
    # High-level evaluation entry point
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def evaluate(payload: dict[str, Any], history: dict[str, list] | None = None) -> dict[str, Any]:
        """
        Primary evaluation method called by gateway.py.

        payload fields:
            trajectory              list[dict]  — ordered agent events
            sub_tasks               int         — oracle minimum step count
            constraint_violations   int         — hard constraint violations
            recovery_episodes       list[dict]  — optional, for FRR and IRS
            ti_score                float|None  — LLM judge score, set by gateway
            context                 str         — free-text task description
            agent_id                str         — agent identifier

        history fields (for CSI, from Supabase):
            pei_scores      list[float]
            irs_scores      list[float]
            outcomes        list[bool]   — True = SAFE, False = UNSAFE

        Returns a dict with all five metrics, verdict, tier, and memory_hit.
        """
        trajectory  = payload.get("trajectory", [])
        l_actual    = len(trajectory)
        l_min       = max(1, payload.get("sub_tasks", 1))
        violations  = payload.get("constraint_violations", 0)
        episodes    = payload.get("recovery_episodes", [])
        ti_raw      = payload.get("ti_score", None)

        pei = HBEvalEngines.calculate_pei(l_min, l_actual, violations)
        irs = HBEvalEngines.calculate_irs(episodes)
        frr = HBEvalEngines.calculate_frr(episodes)
        ti  = HBEvalEngines.calculate_ti(ti_raw)

        # CSI requires historical data passed from gateway (Supabase query)
        csi = None
        if history:
            csi = HBEvalEngines.calculate_csi(
                pei_history     = history.get("pei_scores", []),
                irs_history     = history.get("irs_scores", []),
                outcome_history = history.get("outcomes", []),
            )

        metrics = {"pei": pei, "irs": irs, "frr": frr, "ti": ti, "csi": csi}
        tier    = HBEvalEngines.assign_tier(metrics)
        verdict = "SAFE" if tier is not None or pei >= 0.70 else "UNSAFE"

        # memory_hit is True when at least one recovery episode met C1+C2+C3.
        memory_hit = any(
            HBEvalEngines.classify_recovery_intentionality(ep) == 1
            for ep in episodes
        ) if episodes else False

        return {
            "verdict":    verdict,
            "tier":       tier,
            "metrics":    metrics,
            "memory_hit": memory_hit,
        }
