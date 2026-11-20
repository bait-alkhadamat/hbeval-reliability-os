"""Version 1 of the isolated refund evidence contract."""
from dataclasses import dataclass
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
    if evidence is None or ledger_entry is None or evidence.action != action:
        return "UNKNOWN"
    if not evidence.ledger_receipt or ledger_entry != (action, evidence.ledger_receipt):
        return "UNKNOWN"
    if not scope_digest or not evidence.scope_digest:
        return "UNKNOWN"
    if evidence.scope_digest != scope_digest or evidence.required_test != "refund-commit-lost-response-restart-v1":
        return "RETEST"
    return "APPLIES"
