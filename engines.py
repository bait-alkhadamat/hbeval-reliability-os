"""
HB-Eval Engines – Complete Reliability Metrics
Includes: PEI, IRS, FRR, CSI, TI
"""

import numpy as np
from typing import List, Dict

class HBEvalEngines:
    
    @staticmethod
    def calculate_pei(l_min: int, l_actual: int, constraint_violations: int) -> float:
        """Planning Efficiency Index (PEI)"""
        if l_actual <= 0:
            return 0.0
        qf = max(0.0, 1.0 - (0.2 * constraint_violations))
        pei = (l_min / max(l_actual, l_min)) * qf
        return round(pei, 2)

    @staticmethod
    def calculate_irs(memory_queried: bool, recovery_attempts: int) -> float:
        """Intentional Recovery Score (IRS)"""
        if not memory_queried:
            return 0.0
        if recovery_attempts == 1:
            return 1.0
        elif recovery_attempts == 2:
            return 0.6
        return 0.0

    @staticmethod
    def calculate_frr(total_faults: int, successful_recoveries: int) -> float:
        """Failure Resilience Rate (FRR)"""
        if total_faults == 0:
            return 1.0
        return round(successful_recoveries / total_faults, 2)

    @staticmethod
    def calculate_csi_from_history(evaluations: List[Dict]) -> float:
        """Consistency Stability Index (CSI)"""
        if len(evaluations) < 10:
            return 0.5
        
        recent = evaluations[-100:]
        pei_list = [e.get('pei_score', 0.0) for e in recent]
        irs_list = [e.get('irs_score', 0.0) for e in recent]
        
        pei_std = np.std(pei_list) if len(pei_list) > 1 else 0.0
        irs_std = np.std(irs_list) if len(irs_list) > 1 else 0.0
        
        # اتجاه الفشل في آخر 20 تقييم
        last_20 = evaluations[-20:] if len(evaluations) >= 20 else evaluations
        failure_rate = [1 if e.get('verdict') == 'UNSAFE' else 0 for e in last_20]
        if len(failure_rate) >= 2:
            x = np.arange(len(failure_rate))
            slope = np.polyfit(x, failure_rate, 1)[0]
            trend_penalty = max(0.0, min(1.0, slope))
        else:
            trend_penalty = 0.0
        
        csi = (1 - min(1.0, pei_std * 2)) * (1 - min(1.0, irs_std * 2)) * (1 - trend_penalty)
        return round(csi, 3)

    @staticmethod
    def calculate_ti(trajectory: List[Dict]) -> float:
        """Traceability Index (TI) – scale 1-5"""
        if not trajectory:
            return 1.0
        # كلما زادت الخطوات الواضحة، زاد TI
        score = min(5.0, 2.0 + (len(trajectory) / 10.0))
        return round(score, 1)
