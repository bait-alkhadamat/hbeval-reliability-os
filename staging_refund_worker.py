"""One-shot Railway staging worker for a dedicated Stripe test charge.

Run with python -m staging_refund_worker and mount a persistent volume at /data.
The supervisor restarts the process after exit 23. Only the first process sends.
"""
import hashlib
import os
import sqlite3
import uuid

import httpx

from action_evidence import Refund
from refund_recovery import ProviderReceipt, reconcile_refund


def run(db, stripe, charge, worker_id):
    tenant = "hb-staging"
    op = hashlib.sha256(f"{tenant}:{charge}".encode()).hexdigest()
    db.execute("""CREATE TABLE IF NOT EXISTS intents (
        op TEXT PRIMARY KEY, state TEXT NOT NULL, sender TEXT, receiver TEXT, receipt TEXT
    )""")
    db.execute("BEGIN IMMEDIATE")
    db.execute("INSERT OR IGNORE INTO intents(op,state) VALUES(?, 'READY')", (op,))
    claimed = db.execute(
        "UPDATE intents SET state='UNKNOWN',sender=? WHERE op=? AND state='READY'",
        (worker_id, op),
    ).rowcount
    db.commit()
    if claimed:
        response = stripe.post("/v1/refunds", headers={"Idempotency-Key": op}, data={
            "charge": charge, "amount": "1", "metadata[hb_operation]": op,
            "metadata[hb_tenant]": tenant,
        })
        response.raise_for_status()
        print(f"worker={worker_id} operation={op} accepted; exiting before receipt", flush=True)
        return 23

    page = stripe.get("/v1/refunds", params={"charge": charge, "limit": 100}).raise_for_status().json()
    action = Refund(tenant, op, charge, 1, "USD")
    rows = page["data"]
    if page["has_more"] or len(rows) != 1:
        return 2
    row = rows[0]
    metadata = row["metadata"]
    observed = Refund(metadata.get("hb_tenant"), metadata.get("hb_operation"), row["charge"],
                      row["amount"], row["currency"].upper())
    evidence = ProviderReceipt(observed, row["id"], row["status"] == "succeeded" and row["livemode"] is False)
    state, receipt = reconcile_refund(action, lambda _: [evidence])
    if state != "CONFIRMED":
        return 2
    db.execute("UPDATE intents SET state=?,receipt=?,receiver=? WHERE op=?", (state, receipt, worker_id, op))
    db.commit()
    print(f"worker={worker_id} operation={op} state={state} receipt={receipt} effects=1", flush=True)
    return 0


def main():
    key = os.environ["STRIPE_TEST_SECRET_KEY"]
    charge = os.environ["HB_REFUND_TEST_CHARGE"]
    if (os.environ.get("RAILWAY_ENVIRONMENT_ID") != "ed0d3ec2-8c0d-4d74-b619-82dccde6c601"
            or not key.startswith(("sk_test_", "rk_test_")) or not charge.startswith("ch_")
            or os.environ.get("RAILWAY_VOLUME_MOUNT_PATH") != "/data"):
        raise SystemExit("Require staging, mounted /data, a test key and a dedicated test charge")
    with httpx.Client(base_url="https://api.stripe.com", auth=(key, ""), timeout=20) as stripe:
        record = stripe.get(f"/v1/charges/{charge}").raise_for_status().json()
        if (record["livemode"] is not False or record["currency"] != "usd"
                or record["metadata"].get("hb_experiment") != "refund-worker-staging"):
            raise SystemExit("Charge is outside the staging experiment")
        with sqlite3.connect("/data/refund-staging.sqlite") as db:
            return run(db, stripe, charge, uuid.uuid4().hex)


if __name__ == "__main__":
    raise SystemExit(main())
