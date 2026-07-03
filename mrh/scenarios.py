"""The reference scenarios: one positive path, the four reference negative tests, and a
governed-exception demonstration. Each returns (name, passed, detail)."""
import time
from .harness import Harness

def _slice(h, before):
    return [e["event.type"] for e in h.c5.events[before:]]

def positive_path():
    h = Harness(); now = time.time()
    r = h.governed_flow({"subject_id": "cs-agent-01", "action_class": "data.read", "target": "orders-db"}, now)
    types = [e["event.type"] for e in h.c5.events]
    ok = r.get("admitted") is True and types == ["PERMIT", "CC_COMPILED", "EXECUTION_AUTHORIZED"]
    return ("Positive path (permitted read)", ok, f"chain={types}")

def nt001_non_cc_blocked():
    h = Harness(); now = time.time()
    r = h.present(None, now, "cs-agent-01")
    ok = (r["admitted"] is False and r["block_reason"] == "CC_NOT_FOUND"
          and _slice(h, 0) == ["EXECUTION_BLOCKED"])
    return ("NT-001 non-CC execution blocked", ok, f"reason={r.get('block_reason')}")

def nt002_expired_cc_blocked():
    h = Harness(); now = time.time()
    cc = h.c7.compile({"subject_id": "cs-agent-01", "action_class": "data.read", "target": "orders-db"}, now, ttl=-10)
    r = h.present(cc, now, "cs-agent-01")
    ok = r["admitted"] is False and r["block_reason"] == "CC_EXPIRED"
    return ("NT-002 expired CC blocked", ok, f"reason={r.get('block_reason')}")

def nt003_replay_blocked():
    h = Harness(); now = time.time()
    cc = h.c7.compile({"subject_id": "cs-agent-01", "action_class": "data.read", "target": "orders-db"}, now)
    first = h.present(cc, now, "cs-agent-01")
    second = h.present(cc, now, "cs-agent-01")
    ok = first["admitted"] is True and second["admitted"] is False and second["block_reason"] == "CC_ALREADY_REDEEMED"
    return ("NT-003 replay blocked", ok, f"replay_reason={second.get('block_reason')}")

def nt004_unregistered_context_blocked():
    h = Harness(); now = time.time()
    r = h.governed_flow({"subject_id": "cs-agent-01", "action_class": "data.read", "target": "shadow-endpoint"}, now)
    types = [e["event.type"] for e in h.c5.events]
    ok = (r["outcome"] == "BLOCKED" and types == ["CONTEXT_FAILURE"]
          and "PERMIT" not in types and "CC_COMPILED" not in types)
    return ("NT-004 unregistered context blocked", ok, f"events={types}")

def governed_exception():
    h = Harness(); now = time.time()
    action = {"subject_id": "cs-agent-01", "action_class": "data.export", "target": "billing"}
    denied = h.governed_flow(action, now)
    auth = h.c1.issue_authorization(action, now)
    first = h.governed_flow(action, now, authorization=auth)
    basis = [e for e in h.c5.events if e["event.type"] == "PERMIT"][-1]["event.decision_basis"]
    cc_carries_ref = first.get("cc", {}).get("auth_ref") == auth["auth_id"]
    auth_id_logged = any(e.get("event.auth_id") == auth["auth_id"] for e in h.c5.events)
    reuse = h.governed_flow(action, now, authorization=auth)
    ok = (denied["outcome"] == "DENIED" and first.get("admitted") is True
          and basis == "PERMIT_WITH_AUTHORIZATION" and cc_carries_ref and auth_id_logged
          and reuse["outcome"] == "DENIED")
    return ("Governed exception (signed, single-use, PERMIT_WITH_AUTHORIZATION)", ok,
            f"basis={basis}, cc_carries_auth_ref={cc_carries_ref}, auth_id_logged={auth_id_logged}, "
            f"auth_reuse_denied={reuse['outcome'] == 'DENIED'}")

ALL = [positive_path, nt001_non_cc_blocked, nt002_expired_cc_blocked,
       nt003_replay_blocked, nt004_unregistered_context_blocked, governed_exception]
