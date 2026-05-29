class HBEvalEngines:
    @staticmethod
    def calculate_pei(l_min: int, l_actual: int, constraint_violations: int) -> float:
        if l_actual <= 0: return 0.0
        qf = max(0.0, 1.0 - (0.2 * constraint_violations))
        pei = (l_min / max(l_actual, l_min)) * qf
        return round(pei, 2)

    @staticmethod
    def calculate_irs(memory_queried: bool, recovery_attempts: int) -> float:
        if not memory_queried: return 0.0
        if recovery_attempts == 1: return 1.0
        elif recovery_attempts == 2: return 0.6
        return 0.0

    @staticmethod
    def calculate_frr(total_faults: int, successful_recoveries: int) -> float:
        if total_faults == 0: return 1.0
        return round(successful_recoveries / total_faults, 2)
