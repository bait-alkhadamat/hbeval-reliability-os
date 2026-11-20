"""Stripe sandbox experiment with a durable intent and a restarted worker."""
import hashlib
import multiprocessing
import os
import sqlite3
import uuid

import httpx
import pytest

from action_evidence import Refund
from refund_recovery import ProviderReceipt, reconcile_refund


def client():
    key = os.environ["STRIPE_TEST_SECRET_KEY"]
    assert key.startswith(("sk_test_", "rk_test_"))
    return httpx.Client(base_url="https://api.stripe.com", auth=(key, ""), timeout=20)


def worker(path):
    with sqlite3.connect(path) as db, client() as stripe:
        charge, op, state = db.execute("SELECT charge, op, state FROM intent").fetchone()
        if state == "READY":
            db.execute("UPDATE intent SET state='UNCERTAIN'")
            db.commit()
            # Drop the successful response before decoding or persisting the receipt.
            with stripe.stream("POST", "/v1/refunds", headers={"Idempotency-Key": op},
                               data={"charge": charge, "amount": "1", "metadata[hb_operation]": op}) as response:
                response.raise_for_status()
                os._exit(23)
        assert state == "UNCERTAIN"
        action = Refund("hb-sandbox", op, charge, 1, "USD")

        def lookup(_):
            page = stripe.get("/v1/refunds", params={"charge": charge}).raise_for_status().json()
            assert not page["has_more"] and len(page["data"]) == 1
            row = page["data"][0]
            observed = Refund("hb-sandbox", row["metadata"]["hb_operation"], row["charge"],
                              row["amount"], row["currency"].upper())
            return [ProviderReceipt(observed, row["id"], row["status"] == "succeeded")]

        status, receipt = reconcile_refund(action, lookup)
        assert status == "CONFIRMED" and receipt.startswith("re_")
        db.execute("UPDATE intent SET state=?, receipt=?", (status, receipt))


def run_worker(path):
    process = multiprocessing.get_context("spawn").Process(target=worker, args=(path,))
    process.start()
    try:
        process.join(60)
        assert not process.is_alive()
        return process.exitcode
    finally:
        if process.is_alive():
            process.kill()
            process.join()
        process.close()


def test_stripe_worker_restart(tmp_path):
    if os.getenv("HB_STRIPE_RESTART_TEST") != "1":
        pytest.skip("Dedicated sandbox experiment")
    with client() as stripe:
        response = stripe.post("/v1/payment_intents", headers={"Idempotency-Key": uuid.uuid4().hex},
                             data={"amount": "200", "currency": "usd", "payment_method": "pm_card_visa",
                                   "return_url": "https://example.com/stripe-test-return", "confirm": "true",
                                   "description": "Sandbox worker recovery experiment"})
        if response.is_error:
            error = response.json()["error"]
            pytest.fail(f"Sandbox setup: {error.get('code')} {error.get('message')}")
        intent = response.json()
        assert intent["livemode"] is False and intent["status"] == "succeeded"
        charge = intent["latest_charge"]
        op = hashlib.sha256(f"hb-restart:{charge}".encode()).hexdigest()
        path = tmp_path / "intent.sqlite"
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE intent (charge TEXT PRIMARY KEY, op TEXT, state TEXT, receipt TEXT)")
            db.execute("INSERT INTO intent VALUES (?, ?, 'READY', NULL)", (charge, op))
            db.commit()
            assert run_worker(path) == 23
            assert db.execute("SELECT state, receipt FROM intent").fetchone() == ("UNCERTAIN", None)
            assert run_worker(path) == 0
            state, receipt = db.execute("SELECT state, receipt FROM intent").fetchone()
            assert state == "CONFIRMED"
        page = stripe.get("/v1/refunds", params={"charge": charge}).raise_for_status().json()
        assert not page["has_more"] and [r["id"] for r in page["data"]] == [receipt]
        print("Worker restarted automatically; state=CONFIRMED; Stripe refund count=1")
