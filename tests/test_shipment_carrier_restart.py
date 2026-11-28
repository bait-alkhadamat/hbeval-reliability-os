"""Exercise the shipment contract against a durable, isolated carrier ledger."""
import multiprocessing
import os
import sqlite3
import tempfile
import unittest
import uuid
from pathlib import Path
from dataclasses import astuple, replace

from action_evidence import Shipment, ShipmentEvidenceV1, assess_shipment, dependency_scope


def _dispatch(path, shipment):
    with sqlite3.connect(path) as carrier:
        carrier.execute("CREATE TABLE shipments (tenant, operation_id, order_id, destination, receipt)")
        carrier.execute("INSERT INTO shipments VALUES (?, ?, ?, ?, ?)",
                        (*astuple(shipment), uuid.uuid4().hex))
    os._exit(23)  # The carrier committed. The sender never delivered its response.


class CarrierRestartTests(unittest.TestCase):
    def test_shipment_receipt_after_sender_exit(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "carrier.sqlite"
        requested = Shipment("tenant-a", "ship-1", "order-7", "d" * 64)
        versions = {"identity": "a" * 64, "carrier": "b" * 64}
        scope = dependency_scope(requested, versions, "c" * 64)
        sender = multiprocessing.get_context("spawn").Process(target=_dispatch, args=(path, requested))
        sender.start()
        try:
            sender.join(10)
            assert sender.exitcode == 23
        finally:
            if sender.is_alive():
                sender.kill()
                sender.join()
            sender.close()

        assert assess_shipment(requested, scope, None, None) == "UNKNOWN"
        with sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True) as carrier:
            (row,) = carrier.execute("SELECT tenant, operation_id, order_id, destination, receipt FROM shipments").fetchall()
        observed = Shipment(*row[:4])
        receipt = row[4]
        evidence = ShipmentEvidenceV1(requested, scope, receipt)
        entry = (observed, receipt)
        assert assess_shipment(requested, scope, evidence, entry) == "APPLIES"
        updated = dependency_scope(requested, {**versions, "carrier": "e" * 64}, "c" * 64)
        assert assess_shipment(requested, updated, evidence, entry) == "RETEST"
        wrong_tenant = replace(observed, tenant="tenant-b")
        assert assess_shipment(requested, scope, evidence, (wrong_tenant, receipt)) == "UNKNOWN"
