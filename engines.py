"""
HB-Eval Engines – Mathematical core for reliability metrics
Includes: PEI, IRS, FRR, CSI (Consistency Stability Index)
"""

import numpy as np
from typing import List, Dict

class HBEvalEngines:
    @staticmethod
    def calculate_pei(l_min: int, l_actual: int, constraint_violations: int) -> float:
        """
        Planning Efficiency Index (PEI)
        Formula: (L_min / L_actual) * QF
        QF = 1 - 0.2 * violations, clamped to [0,1]
        """
        if l_actual <= 0:
            return 0.0
        qf = max(0.0, 1.0 - (0.2 * constraint_violations))
        pei = (l_min / max(l_actual, l_min)) * qf
        return round(pei, 2)

    @staticmethod
    def calculate_irs(memory_queried: bool, recovery_attempts: int) -> float:
        """
        Intentional Recovery Score (IRS)
        1.0 = perfect memory-guided recovery in one attempt
        0.6 = recovery in two attempts
        0.0 = no memory query or too many attempts
        """
        if not memory_queried:
            return 0.0
        if recovery_attempts == 1:
            return 1.0
        elif recovery_attempts == 2:
            return 0.6
        else:
            return 0.0

    @staticmethod
    def calculate_frr(total_faults: int, successful_recoveries: int) -> float:
        """
        Failure Resilience Rate (FRR)
        Ratio of successful recoveries to total faults
        """
        if total_faults == 0:
            return 1.0
        return round(successful_recoveries / total_faults, 2)

    @staticmethod
    def calculate_csi_from_history(evaluations: List[Dict]) -> float:
        """
        Consistency Stability Index (CSI)
        Measures stability over time using last 100 evaluations.
        Returns value between 0 and 1.
        1 = perfectly stable, 0 = completely unstable.
        """
        if len(evaluations) < 10:
            return 0.5  # insufficient data
        
        # Use last 100 or all if less
        n = min(100, len(evaluations))
        recent = evaluations[-n:]
        
        pei_list = [e.get('pei_score', 0.0) for e in recent]
        irs_list = [e.get('irs_score', 0.0) for e in recent]
        
        pei_std = np.std(pei_list) if len(pei_list) > 1 else 0.0
        irs_std = np.std(irs_list) if len(irs_list) > 1 else 0.0
        
        # Failure trend: slope of UNSAFE rate in last 20
        last_20 = evaluations[-20:] if len(evaluations) >= 20 else evaluations
        failure_rate = [1 if e.get('verdict') == 'UNSAFE' else 0 for e in last_20]
        if len(failure_rate) >= 2:
            x = np.arange(len(failure_rate))
            slope = np.polyfit(x, failure_rate, 1)[0]
            trend_penalty = max(0.0, min(1.0, slope))
        else:
            trend_penalty = 0.0
        
        # CSI = (1 - normalized std_pei) * (1 - normalized std_irs) * (1 - trend_penalty)
        pei_factor = 1 - min(1.0, pei_std * 2)  # std up to 0.5 gives factor 0
        irs_factor = 1 - min(1.0, irs_std * 2)
        csi = pei_factor * irs_factor * (1 - trend_penalty)
        return round(csi, 3)
