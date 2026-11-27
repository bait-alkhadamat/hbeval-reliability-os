"""Frozen paired evaluation registered in PR 23. Run with python -m unittest discover -s tests -p test_registered_cases.py -v."""
import hashlib
import unittest
from dataclasses import replace

from action_evidence import (
    Refund, RefundEvidenceV1, Shipment, ShipmentEvidenceV1,
    assess_refund, assess_shipment, dependency_scope,
)


def digest(label):
    return hashlib.sha256(label.encode()).hexdigest()


class RegisteredCases(unittest.TestCase):
    def test_registered_pairs(self):
        refund = Refund("tenant", "refund-1", "payment", 100, "USD")
        shipment = Shipment("tenant", "shipment-1", "order", digest("destination"))
        versions = {key: digest(key) for key in ("identity", "payment", "carrier", "other")}
        conditions = digest("conditions")
        actions = (
            (refund, RefundEvidenceV1, assess_refund, "refund-receipt"),
            (shipment, ShipmentEvidenceV1, assess_shipment, "carrier-receipt"),
        )
        pairs = (
            ("H1", ("RETEST", "UNKNOWN")),
            ("H2", ("UNKNOWN", "RETEST")),
            ("H3", ("RETEST", "UNKNOWN")),
            ("H4", ("APPLIES", "APPLIES")),
        )
        for case, expected in pairs:
            candidate = versions.copy()
            current_conditions = conditions
            ledger = {refund: (refund, "refund-receipt"), shipment: (shipment, "carrier-receipt")}
            if case == "H1":
                candidate["payment"] = digest("new-payment")
                del ledger[shipment]
            elif case == "H2":
                candidate["identity"] = digest("new-identity")
                ledger[refund] = (replace(refund, tenant="other-tenant"), "refund-receipt")
            elif case == "H3":
                current_conditions = digest("new-conditions")
                del candidate["carrier"]
            else:
                candidate = dict(reversed(candidate.items()))
                candidate["other"] = digest("new-other")

            for (action, evidence_type, assess, receipt), wanted in zip(actions, expected, strict=True):
                with self.subTest(case=case, action=type(action).__name__):
                    baseline = dependency_scope(action, versions, conditions)
                    evidence = evidence_type(action, baseline, receipt)
                    current = dependency_scope(action, candidate, current_conditions)
                    observed = assess(action, current, evidence, ledger.get(action))
                    self.assertEqual(observed, wanted)
