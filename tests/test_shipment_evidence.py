"""Paired controls use synthetic payment and carrier receipts."""
import pytest
from action_evidence import (Refund, Shipment, RefundEvidenceV1, ShipmentEvidenceV1,
                             assess_refund, assess_shipment, dependency_scope)

@pytest.mark.parametrize("component,version,expected", [
    ("unrelated", "d"*64, ("APPLIES", "APPLIES")),
    ("identity", "d"*64, ("RETEST", "RETEST")),
    ("payment", "d"*64, ("RETEST", "APPLIES")),
    ("carrier", "d"*64, ("APPLIES", "RETEST")),
    ("carrier", "", ("APPLIES", "UNKNOWN")),
])
def test_dependency_changes(component, version, expected):
    baseline = {"payment": "a"*64, "carrier": "b"*64, "identity": "c"*64}
    candidate = {**baseline, component: version}
    conditions = "e"*64
    refund = Refund("tenant", "r1", "p1", 3500, "USD")
    shipment = Shipment("tenant", "s1", "order1", "f"*64)
    results = []
    for action, evidence_type, assess, receipt in [
        (refund, RefundEvidenceV1, assess_refund, "payment-receipt"),
        (shipment, ShipmentEvidenceV1, assess_shipment, "carrier-receipt"),
    ]:
        evidence = evidence_type(action, dependency_scope(action, baseline, conditions), receipt)
        scope = dependency_scope(action, candidate, conditions)
        results.append(assess(action, scope, evidence, (action, receipt)))
        assert assess(action, scope, evidence, None) == "UNKNOWN"
    assert tuple(results) == expected
