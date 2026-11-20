"""Isolated refund experiment. Each provider effect models one executed refund."""
import hashlib
import json
import multiprocessing
import os
import sqlite3
from uuid import uuid4

import pytest

from action_evidence import Refund
from dataclasses import asdict, replace


def digest(action):
    return hashlib.sha256(json.dumps(asdict(action), sort_keys=True).encode()).hexdigest()


def initialize(root):
    with sqlite3.connect(root / "gateway") as db:
        db.execute("CREATE TABLE intents(tenant, op, key, payload, PRIMARY KEY(tenant,op))")
    with sqlite3.connect(root / "provider") as db:
        db.execute("CREATE TABLE effects(receipt PRIMARY KEY, tenant, op, key, payload, amount, currency)")
        db.execute("CREATE TABLE attempts(tenant, op, key, payload, result)")


def dispatch(root, action, key, policy, protected=True):
    payload = digest(action)
    if policy == "gateway":
        with sqlite3.connect(root / "gateway") as db:
            db.execute("INSERT OR IGNORE INTO intents VALUES(?,?,?,?)",
                       (action.tenant, action.operation_id, key, payload))
            binding = db.execute("SELECT key,payload FROM intents WHERE tenant=? AND op=?",
                                 (action.tenant, action.operation_id)).fetchone()
            if binding != (key, payload):
                return "CONFLICT"
    with sqlite3.connect(root / "provider") as db:
        db.execute("BEGIN IMMEDIATE")
        previous = db.execute("SELECT payload,receipt FROM effects WHERE tenant=? AND key=?",
                              (action.tenant, key)).fetchone()
        if protected and policy != "raw" and previous:
            result = previous[1] if previous[0] == payload else "CONFLICT"
        else:
            result = uuid4().hex
            db.execute("INSERT INTO effects VALUES(?,?,?,?,?,?,?)",
                       (result, action.tenant, action.operation_id, key, payload,
                        action.amount_minor, action.currency))
        db.execute("INSERT INTO attempts VALUES(?,?,?,?,?)",
                   (action.tenant, action.operation_id, key, payload, result))
    return result


def retry_after_timeout(root, action, key, policy, protected, lookup):
    if policy == "gateway" and not protected:
        return reconcile(lookup)
    return dispatch(root, action, key, policy, protected)


def retry_worker(root, action, key, policy, output):
    output.put(retry_after_timeout(root, action, key, policy, True, None))


def crash_after_commit(root, action, policy):
    dispatch(root, action, "k", policy)
    os._exit(23)


def race(root, action, policy, barrier, results):
    with sqlite3.connect(root / "provider") as db:
        assert db.execute("SELECT COUNT(*) FROM effects").fetchone()[0] == 0
    barrier.wait(timeout=10)
    results.put(dispatch(root, action, "k", policy))


def reconcile(lookup):
    try:
        rows = lookup()
    except TimeoutError:
        return "UNKNOWN"
    return rows[0][0] if len(rows) == 1 else "UNKNOWN"


@pytest.mark.parametrize("policy", ["raw", "provider", "gateway"])
@pytest.mark.parametrize("scenario", ["retry", "conflict", "race", "new_key", "opaque"])
def test_dispatch(tmp_path, policy, scenario):
    initialize(tmp_path)
    action = Refund("tenant-a", "op-1", "payment-1", 3500, "USD")
    ctx = multiprocessing.get_context("spawn")
    if scenario == "race":
        results = ctx.Queue()
        barrier = ctx.Barrier(2)
        workers = [ctx.Process(target=race, args=(tmp_path, action, policy, barrier, results))
                   for _ in range(2)]
        for worker in workers:
            worker.start()
        try:
            for worker in workers:
                worker.join(15)
                assert worker.exitcode == 0
            receipts = [results.get(timeout=2) for _ in workers]
        finally:
            for worker in workers:
                if worker.is_alive():
                    worker.kill()
                worker.join()
            results.close()
    elif scenario == "opaque":
        dispatch(tmp_path, action, "k", policy, protected=False)

        def unavailable():
            raise TimeoutError

        assert reconcile(unavailable) == "UNKNOWN"
        assert reconcile(lambda: []) == "UNKNOWN"
        outcome = retry_after_timeout(tmp_path, action, "k", policy, False, unavailable)
        if policy == "gateway":
            assert outcome == "UNKNOWN"
    else:
        first = ctx.Process(target=crash_after_commit, args=(tmp_path, action, policy))
        first.start()
        first.join(15)
        if first.is_alive():
            first.kill()
            first.join()
        assert first.exitcode == 23
        changed = replace(action, amount_minor=7000) if scenario == "conflict" else action
        key = "replacement" if scenario == "new_key" else "k"
        output = ctx.Queue()
        replacement = ctx.Process(target=retry_worker, args=(tmp_path, changed, key, policy, output))
        replacement.start()
        try:
            replacement.join(15)
            assert replacement.exitcode == 0
            result = output.get(timeout=2)
        finally:
            if replacement.is_alive():
                replacement.kill()
                replacement.join()
            output.close()
    with sqlite3.connect(f"file:{tmp_path}/provider?mode=ro", uri=True) as db:
        effects = db.execute("SELECT receipt,amount,currency FROM effects ORDER BY rowid").fetchall()
        attempts = db.execute("SELECT result FROM attempts ORDER BY rowid").fetchall()
    blocked = policy == "gateway" and scenario in {"new_key", "conflict", "opaque"}
    duplicate = policy == "raw" or (policy == "provider" and scenario in {"new_key", "opaque"})
    assert len(attempts) == (1 if blocked else 2)
    assert len(effects) == (2 if duplicate else 1)
    assert effects[0][1:] == (3500, "USD")
    if policy == "gateway":
        with sqlite3.connect(tmp_path / "gateway") as db:
            assert db.execute("SELECT COUNT(*) FROM intents").fetchone() == (1,)
    if scenario == "race":
        assert set(receipts) == {row[0] for row in effects}
    elif scenario == "retry" and not duplicate:
        assert result == attempts[0][0] == effects[0][0]
    elif scenario == "conflict" and policy != "raw" or scenario == "new_key" and blocked:
        assert result == "CONFLICT"


def test_delayed_receipt(tmp_path):
    from refund_recovery import ProviderReceipt, recover_refund

    initialize(tmp_path)
    action = Refund("a", "refund-1", "pay-1", 3500, "USD")
    receipt = dispatch(tmp_path, action, "key", "gateway")
    states = []
    for tick in range(4):
        def lookup(request):
            with sqlite3.connect(tmp_path / "provider") as db:
                rows = db.execute("SELECT receipt,payload FROM effects WHERE tenant=? AND op=?",
                                  (request.tenant, request.operation_id)).fetchall()
            return [ProviderReceipt(action, ref, True) for ref, payload in rows
                    if tick >= 3 and payload == digest(action)]
        states.append(recover_refund(action, lookup, now=tick, protected_until=10))
        with sqlite3.connect(tmp_path / "provider") as db:
            assert db.execute("SELECT COUNT(*) FROM attempts").fetchone() == (1,)
    assert states == [("UNKNOWN", None)] * 3 + [("CONFIRMED", receipt)]


@pytest.mark.parametrize("now,expected_attempts", [(9, 2), (10, 1), (11, 1)])
def test_key_expiry(tmp_path, now, expected_attempts):
    from refund_recovery import recover_refund

    initialize(tmp_path)
    action = Refund("a", "refund-1", "pay-1", 3500, "USD")
    dispatch(tmp_path, action, "k", "gateway")
    def retry(request):
        dispatch(tmp_path, request, "k", "gateway", protected=now < 10)
    assert recover_refund(action, lambda _: [], now=now, protected_until=10,
                          retry=retry) == ("UNKNOWN", None)
    with sqlite3.connect(tmp_path / "provider") as db:
        assert db.execute("SELECT COUNT(*) FROM attempts").fetchone() == (expected_attempts,)
        assert db.execute("SELECT COUNT(*) FROM effects").fetchone() == (1,)


def test_currency_conflict_and_tenant_isolation(tmp_path):
    initialize(tmp_path)
    a = Refund("a", "same-ref", "pay-a", 3500, "USD")
    b = replace(a, tenant="b", payment_id="pay-b", currency="EUR")
    first = dispatch(tmp_path, a, "same-key", "gateway")
    assert dispatch(tmp_path, replace(a, currency="EUR"), "same-key", "gateway") == "CONFLICT"
    second = dispatch(tmp_path, b, "same-key", "gateway")
    assert first != second
    with sqlite3.connect(tmp_path / "provider") as db:
        assert db.execute("SELECT tenant,currency,receipt FROM effects ORDER BY tenant").fetchall() == [
            ("a", "USD", first), ("b", "EUR", second)]
        assert db.execute("SELECT COUNT(*) FROM attempts").fetchone() == (2,)
