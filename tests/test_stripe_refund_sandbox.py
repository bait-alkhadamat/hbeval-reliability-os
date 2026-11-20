"""Opt-in, in-process HB-Eval Gateway to Stripe test-mode round trip.

Provide STRIPE_TEST_SECRET_KEY and HB_REFUND_TEST_CHARGE (fresh succeeded USD
test charge dedicated to this test). The route exists only in this fixture.
"""
import hashlib
import os
import re

import httpx
import pytest

from action_evidence import Refund
from refund_recovery import ProviderReceipt, reconcile_refund


def exercise(world, stripe, charge):
    info = stripe.get(f"/v1/charges/{charge}").raise_for_status().json()
    assert info["id"] == charge and info["livemode"] is False
    assert info["status"] == "succeeded" and info["currency"] == "usd"
    assert info["amount_refunded"] == 0 and info["amount"] >= 1
    op = hashlib.sha256(f"hb-sandbox-refund:{charge}".encode()).hexdigest()
    action = Refund("hb-sandbox", op, charge, 1, "USD")

    def refund():
        response = stripe.post("/v1/refunds", headers={"Idempotency-Key": op},
                               data={"charge": charge, "amount": "1",
                                     "metadata[hb_operation]": op})
        return {"receipt": response.raise_for_status().json()["id"]}

    path = "/_experiment/refund"
    world.gateway.app.add_api_route(path, refund, methods=["POST"])
    try:
        reply = world.http.post(path)
        assert reply.status_code == 200
    finally:
        world.gateway.app.router.routes.remove(next(r for r in world.gateway.app.router.routes
                                                   if getattr(r, "path", "") == path))

    def lookup(_):
        page = stripe.get("/v1/refunds", params={"charge": charge, "limit": 100}).raise_for_status().json()
        assert not page["has_more"] and len(page["data"]) == 1
        row = page["data"][0]
        assert row["livemode"] is False and row["charge"] == charge
        observed = Refund("hb-sandbox", row["metadata"]["hb_operation"], row["charge"],
                          row["amount"], row["currency"].upper())
        return [ProviderReceipt(observed, row["id"], row["status"] == "succeeded")]
    assert reconcile_refund(action, lookup) == ("CONFIRMED", reply.json()["receipt"])


def test_stripe_sandbox(world):
    key = os.getenv("STRIPE_TEST_SECRET_KEY")
    charge = os.getenv("HB_REFUND_TEST_CHARGE")
    if not key or not charge:
        pytest.skip("Stripe test credentials and dedicated charge required")
    assert key.startswith(("sk_test_", "rk_test_")) and re.fullmatch(r"(ch|pi)_[A-Za-z0-9]+", charge)
    with httpx.Client(base_url="https://api.stripe.com", auth=(key, ""), timeout=15) as stripe:
        if charge.startswith("pi_"):
            intent = stripe.get(f"/v1/payment_intents/{charge}").raise_for_status().json()
            assert intent["id"] == charge and intent["livemode"] is False
            assert intent["status"] == "succeeded" and intent["currency"] == "usd"
            charge = intent["latest_charge"]
            assert isinstance(charge, str) and re.fullmatch(r"ch_[A-Za-z0-9]+", charge)
        exercise(world, stripe, charge)


def test_gateway_refund_transport_control(world):
    from urllib.parse import parse_qs

    charge = "ch_fixture"
    records = []
    def transport(request):
        if request.url.path == f"/v1/charges/{charge}":
            data = dict(id=charge, livemode=False, status="succeeded", currency="usd",
                        amount_refunded=0, amount=100)
        elif request.method == "POST" and request.url.path == "/v1/refunds":
            form = parse_qs(request.content.decode())
            assert request.headers["Idempotency-Key"] == form["metadata[hb_operation]"][0]
            records.append(dict(id="re_fixture", livemode=False, charge=form["charge"][0],
                                amount=int(form["amount"][0]), currency="usd", status="succeeded",
                                metadata={"hb_operation": form["metadata[hb_operation]"][0]}))
            data = records[-1]
        else:
            assert request.method == "GET" and request.url.params["charge"] == charge
            data = dict(has_more=False, data=records)
        return httpx.Response(200, json=data)
    with httpx.Client(base_url="https://example.invalid", transport=httpx.MockTransport(transport)) as client:
        exercise(world, client, charge)
