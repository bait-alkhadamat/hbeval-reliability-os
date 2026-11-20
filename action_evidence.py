"""Version 1 of the isolated action evidence contract."""
from dataclasses import dataclass
import hashlib
import json
import re
from collections.abc import Mapping
from typing import Literal


@dataclass(frozen=True)
class Refund:
    tenant: str
    operation_id: str
    payment_id: str
    amount_minor: int
    currency: str


@dataclass(frozen=True)
class RefundEvidenceV1:
    action: Refund
    # Digest of the tested adapter, dependencies and execution conditions.
    scope_digest: str
    ledger_receipt: str
    required_test: str = "refund-commit-lost-response-restart-v1"


def assess_refund(action: Refund, scope_digest: str, evidence: RefundEvidenceV1 | None,
                  ledger_entry: tuple[Refund, str] | None) -> Literal["APPLIES", "RETEST", "UNKNOWN"]:
    """Assess evidence applicability. The result grants no execution permission."""
    return _assess(action, scope_digest, evidence, ledger_entry, "refund-commit-lost-response-restart-v1")


def _assess(action, scope_digest, evidence, ledger_entry, required_test):
    if evidence is None or ledger_entry is None or evidence.action != action:
        return "UNKNOWN"
    if not evidence.ledger_receipt or ledger_entry != (action, evidence.ledger_receipt):
        return "UNKNOWN"
    if not scope_digest or not evidence.scope_digest:
        return "UNKNOWN"
    if evidence.scope_digest != scope_digest or evidence.required_test != required_test:
        return "RETEST"
    return "APPLIES"


@dataclass(frozen=True)
class Shipment:
    tenant: str
    operation_id: str
    order_id: str
    destination_digest: str


@dataclass(frozen=True)
class ShipmentEvidenceV1:
    action: Shipment
    scope_digest: str
    ledger_receipt: str
    required_test: str = "shipment-carrier-receipt-v1"


def assess_shipment(action: Shipment, scope_digest: str, evidence: ShipmentEvidenceV1 | None,
                    ledger_entry: tuple[Shipment, str] | None) -> Literal["APPLIES", "RETEST", "UNKNOWN"]:
    return _assess(action, scope_digest, evidence, ledger_entry, "shipment-carrier-receipt-v1")


def dependency_scope(action: Refund | Shipment, versions: Mapping[str, str], conditions_digest: str) -> str:
    """Compute v1 scope for the declared dependencies. Empty means incomplete evidence."""
    if isinstance(action, Refund):
        adapter = "payment"
    elif isinstance(action, Shipment):
        adapter = "carrier"
    else:
        return ""
    inputs = {"conditions": conditions_digest, "identity": versions.get("identity"), adapter: versions.get(adapter)}
    if any(not isinstance(v, str) or not re.fullmatch(r"[0-9a-f]{64}", v) for v in inputs.values()):
        return ""
    return hashlib.sha256(json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
