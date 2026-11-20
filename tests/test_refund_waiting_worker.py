"""Process-level recovery against a separate, simulated payment tool."""
import json
import multiprocessing
import sqlite3
import tempfile
import unittest
from dataclasses import astuple
from pathlib import Path

from action_evidence import Refund, RefundEvidenceV1, assess_refund


def submit(intent, channel):
    action = Refund(**json.loads(intent.read_text()))
    channel.send(astuple(action))
    channel.recv()  # The tool commits, but its reply never arrives.


def recover(intent, ledger, channel):
    action = Refund(**json.loads(intent.read_text()))
    with sqlite3.connect(f"{ledger.as_uri()}?mode=ro", uri=True) as db:
        rows = db.execute(
            "SELECT * FROM refunds WHERE tenant=? AND op=?",
            (action.tenant, action.operation_id),
        ).fetchall()
    if len(rows) != 1:
        raise ValueError("Expected one committed refund")
    row = rows[0]
    entry = Refund(*row[:5]), row[5]
    evidence = RefundEvidenceV1(action, "fixture-v1", row[5])
    channel.send((assess_refund(action, "fixture-v1", evidence, entry), row[5]))


class RefundWorkerRestartTest(unittest.TestCase):
    def test_commit_without_reply_then_replace_worker(self):
        ctx = multiprocessing.get_context("spawn")
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "tool.sqlite"
            intent = Path(directory) / "intent.json"
            intent.write_text(json.dumps(dict(tenant="a", operation_id="op-1",
                                              payment_id="p-7", amount_minor=3500,
                                              currency="USD")))
            receipt = "tool-receipt-1"
            parent, child = ctx.Pipe()
            with parent, child:
                worker = ctx.Process(target=submit, args=(intent, child))
                worker.start()
                try:
                    self.assertTrue(parent.poll(10), "Worker never submitted the refund")
                    request = parent.recv()
                    with sqlite3.connect(ledger) as db:
                        db.execute("CREATE TABLE refunds (tenant, op, payment, amount, currency, receipt)")
                        db.execute("INSERT INTO refunds VALUES (?, ?, ?, ?, ?, ?)", (*request, receipt))
                    self.assertTrue(worker.is_alive())
                finally:
                    worker.kill()
                    worker.join(10)
                self.assertIsNotNone(worker.exitcode)
                self.assertNotEqual(worker.exitcode, 0)

            parent, child = ctx.Pipe()
            with parent, child:
                replacement = ctx.Process(target=recover, args=(intent, ledger, child))
                replacement.start()
                try:
                    replacement.join(10)
                    self.assertEqual(replacement.exitcode, 0)
                    self.assertTrue(parent.poll(1))
                    self.assertEqual(parent.recv(), ("APPLIES", receipt))
                finally:
                    if replacement.is_alive():
                        replacement.kill()
                        replacement.join(10)
            with sqlite3.connect(ledger) as db:
                self.assertEqual(db.execute("SELECT * FROM refunds").fetchall(),
                                 [("a", "op-1", "p-7", 3500, "USD", receipt)])
