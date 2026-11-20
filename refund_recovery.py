"""Reconcile an uncertain refund using the provider's independent records."""
from dataclasses import dataclass

from action_evidence import Refund


@dataclass(frozen=True)
class ProviderReceipt:
    action: Refund
    receipt: str
    succeeded: bool


def reconcile_refund(action, lookup):
    try:
        matches = [row for row in lookup(action)
                   if row.action.tenant == action.tenant and
                   row.action.operation_id == action.operation_id]
    except TimeoutError:
        return "UNKNOWN", None
    if len(matches) == 1:
        row = matches[0]
        if row.action == action and row.succeeded and row.receipt:
            return "CONFIRMED", row.receipt
    return "UNKNOWN", None


def recover_refund(action, lookup, *, now, protected_until, retry=None):
    result = reconcile_refund(action, lookup)
    if result[0] == "CONFIRMED" or retry is None or now >= protected_until:
        return result
    # Caller supplies a scoped, same-payload, same-key retry only when protected.
    retry(action)
    return reconcile_refund(action, lookup)
