"""Isolated payment-tool ledger, persisted independently of the caller."""
import hashlib
import sqlite3
from dataclasses import astuple, replace

import pytest

from action_evidence import Refund, RefundEvidenceV1, assess_refund


def test_committed_refund_survives_lost_response_and_worker_restart(tmp_path):
    ledger = tmp_path / "payment_tool.sqlite"
    action = Refund("tenant-a", "op-1", "pay-7", 3500, "USD")
    scope = hashlib.sha256(b"fixture:refund-adapter-v1|USD|ledger-v1").hexdigest()

    def payment_tool():
        with sqlite3.connect(ledger) as db:
            db.execute("CREATE TABLE refunds (tenant, op, payment, amount, currency, receipt, PRIMARY KEY(tenant, op))")
            db.execute("INSERT INTO refunds VALUES (?, ?, ?, ?, ?, ?)", (*astuple(action), "receipt-1"))
        raise TimeoutError("reply lost after commit")

    with pytest.raises(TimeoutError):
        payment_tool()
    assert assess_refund(action, scope, None, None) == "UNKNOWN"

    # Fresh connection and independently reloaded operation after worker restart.
    recovered = Refund("tenant-a", "op-1", "pay-7", 3500, "USD")
    with sqlite3.connect(ledger) as db:
        rows = db.execute("SELECT * FROM refunds WHERE tenant=? AND op=?",
                          (recovered.tenant, recovered.operation_id)).fetchall()
    assert len(rows) == 1
    row = rows[0]
    entry = Refund(*row[:5]), row[5]
    evidence = RefundEvidenceV1(recovered, scope, row[5])
    assert assess_refund(recovered, scope, evidence, entry) == "APPLIES"
    assert assess_refund(recovered, "changed-adapter", evidence, entry) == "RETEST"
    assert assess_refund(recovered, scope, evidence, None) == "UNKNOWN"
    assert assess_refund(replace(recovered, amount_minor=7000), scope, evidence, entry) == "UNKNOWN"
    assert assess_refund(replace(recovered, tenant="tenant-b"), scope, evidence, entry) == "UNKNOWN"
    assert assess_refund(recovered, scope, evidence, (recovered, "other-receipt")) == "UNKNOWN"
