"""A terminated worker loses its reply. A new worker consults the tool ledger."""
import hashlib
import multiprocessing
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from dataclasses import astuple

from action_evidence import Refund, RefundEvidenceV1, assess_refund


def _commit_then_exit(path, action):
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE refunds (tenant, op, payment, amount, currency, receipt, PRIMARY KEY(tenant, op))")
        db.execute("INSERT INTO refunds VALUES (?, ?, ?, ?, ?, ?)", (*astuple(action), "receipt-1"))
    os._exit(23)  # Commit completed, no response delivered.


def _recover(path, action, scope):
    with sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True) as db:
        rows = db.execute("SELECT * FROM refunds WHERE tenant=? AND op=?",
                          (action.tenant, action.operation_id)).fetchall()
    assert len(rows) == 1
    row = rows[0]
    entry = Refund(*row[:5]), row[5]
    evidence = RefundEvidenceV1(action, scope, row[5])
    assert assess_refund(action, scope, evidence, entry) == "APPLIES"


def _worker_exit(target, *args):
    worker = multiprocessing.get_context("spawn").Process(target=target, args=args)
    worker.start()
    try:
        worker.join(10)
        assert not worker.is_alive()
        return worker.exitcode
    finally:
        if worker.is_alive():
            worker.kill()
            worker.join()
        worker.close()


class RefundWorkerRestartTests(unittest.TestCase):
    def test_new_worker_recovers_after_commit_without_reply(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "tool.sqlite"
            action = Refund("tenant-a", "op-1", "pay-7", 3500, "USD")
            scope = hashlib.sha256(b"isolated-payment-scope-v1").hexdigest()
            assert _worker_exit(_commit_then_exit, ledger, action) == 23
            assert assess_refund(action, scope, None, None) == "UNKNOWN"
            assert _worker_exit(_recover, ledger, action, scope) == 0
