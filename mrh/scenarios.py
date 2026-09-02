"""The reference scenarios: one positive path, the four reference negative tests, a
governed-exception demonstration, and — added September 2026 — the adversarial scenarios
that reproduce the defects an independent audit found. Each returns (name, passed, detail).

The adversarial group is the important one. The cooperative scenarios show the mechanism
working when called correctly; the adversarial ones are the only evidence that it refuses
when called incorrectly.
"""
import hashlib
import hmac
import time

from .components import _CC_KEY, AuthorizationSpent, _canon
from .harness import Harness


def _slice(h, before):
    return [e["event.type"] for e in h.c5.events[before:]]


def _dummy_permit(h, action, sid="cs-agent-01", basis="PERMIT", auth_id=None):
    """Emit a PERMIT so a directly-compiled commitment has a real permit event to cite."""
    fields = {
        "event.session_id": "sess-" + sid,
        "event.action_spec": action,
        "event.decision_basis": basis,
    }
    if auth_id is not None:
        fields["event.auth_id"] = auth_id
    return h.c5.emit("PERMIT", "C2", sid, **fields)["event.id"]


def _record_compiled(h, cc, permit_event_id, sid="cs-agent-01"):
    """Emit the CC_COMPILED event that governed_flow would have emitted.

    Scenarios that drive C7 directly must still produce a coherent C5 record: an
    EXECUTION_AUTHORIZED citing a commitment that was never recorded as compiled is a
    broken log, and verify_decisions() is right to reject it (that is what h04b asserts).
    """
    h.c5.emit("CC_COMPILED", "C7", sid, **{
        "event.session_id": "sess-" + sid,
        "event.cc_id": cc["cc.id"],
        "event.permit_event_id": permit_event_id,
        "event.action_spec": cc["action"],
    })


# ------------------------------------------------------------ cooperative path
def positive_path():
    h = Harness()
    now = time.time()
    r = h.governed_flow(
        {"subject_id": "cs-agent-01", "action_class": "data.read", "target": "orders-db"}, now)
    types = [e["event.type"] for e in h.c5.events]
    ok = r.get("admitted") is True and types == ["PERMIT", "CC_COMPILED", "EXECUTION_AUTHORIZED"]
    return ("Positive path (permitted read)", ok, f"chain={types}")


def nt001_non_cc_blocked():
    h = Harness()
    now = time.time()
    r = h.present(None, now, "cs-agent-01")
    ok = (r["admitted"] is False and r["block_reason"] == "CC_NOT_FOUND"
          and _slice(h, 0) == ["EXECUTION_BLOCKED"])
    return ("NT-001 non-CC execution blocked", ok, f"reason={r.get('block_reason')}")


def nt002_expired_cc_blocked():
    h = Harness()
    now = time.time()
    action = {"subject_id": "cs-agent-01", "action_class": "data.read", "target": "orders-db"}
    pid = _dummy_permit(h, action)
    cc = h.c7.compile(action, now, permit_event_id=pid, ttl=-10)
    _record_compiled(h, cc, pid)
    r = h.present(cc, now, "cs-agent-01", action)
    ok = r["admitted"] is False and r["block_reason"] == "CC_EXPIRED"
    return ("NT-002 expired CC blocked", ok, f"reason={r.get('block_reason')}")


def nt003_replay_blocked():
    h = Harness()
    now = time.time()
    action = {"subject_id": "cs-agent-01", "action_class": "data.read", "target": "orders-db"}
    pid = _dummy_permit(h, action)
    cc = h.c7.compile(action, now, permit_event_id=pid)
    _record_compiled(h, cc, pid)
    first = h.present(cc, now, "cs-agent-01", action)
    second = h.present(cc, now, "cs-agent-01", action)
    chain_ok, _ = h.c5.verify()
    ok = (first["admitted"] is True and second["admitted"] is False
          and second["block_reason"] == "CC_ALREADY_REDEEMED" and chain_ok)
    return ("NT-003 replay blocked", ok,
            f"replay_reason={second.get('block_reason')}, verify={chain_ok}")


def nt004_unregistered_context_blocked():
    h = Harness()
    now = time.time()
    r = h.governed_flow(
        {"subject_id": "cs-agent-01", "action_class": "data.read", "target": "shadow-endpoint"}, now)
    types = [e["event.type"] for e in h.c5.events]
    ok = (r["outcome"] == "BLOCKED" and types == ["CONTEXT_FAILURE"]
          and "PERMIT" not in types and "CC_COMPILED" not in types)
    return ("NT-004 unregistered context blocked", ok, f"events={types}")


def governed_exception():
    h = Harness()
    now = time.time()
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
            f"basis={basis}, cc_carries_auth_ref={cc_carries_ref}, "
            f"auth_id_logged={auth_id_logged}, auth_reuse_denied={reuse['outcome'] == 'DENIED'}")


# ----------------------------------------------------------- adversarial group
def h01_one_authorization_one_execution():
    """H-01. Two decisions taken on one authorization before any redemption must still
    yield at most one commitment and one execution."""
    h = Harness()
    now = time.time()
    action = {"subject_id": "cs-agent-01", "action_class": "data.export", "target": "billing"}
    auth = h.c1.issue_authorization(action, now)

    d1, _ = h.c2.evaluate(action, auth, now)
    d2, _ = h.c2.evaluate(action, auth, now)          # both PERMIT_WITH_AUTHORIZATION: allowed
    p1 = _dummy_permit(h, action, basis="PERMIT_WITH_AUTHORIZATION", auth_id=auth["auth_id"])
    p2 = _dummy_permit(h, action, basis="PERMIT_WITH_AUTHORIZATION", auth_id=auth["auth_id"])

    cc1 = h.c7.compile(action, now, permit_event_id=p1, authorization=auth)
    _record_compiled(h, cc1, p1)
    second_refused = False
    try:
        h.c7.compile(action, now, permit_event_id=p2, authorization=auth)
    except AuthorizationSpent:
        second_refused = True   # no commitment produced, so nothing to record

    r1 = h.present(cc1, now, "cs-agent-01", action)
    n_exec = sum(1 for e in h.c5.events if e["event.type"] == "EXECUTION_AUTHORIZED")
    chain_ok, _ = h.c5.verify()

    ok = (d1 == d2 == "PERMIT_WITH_AUTHORIZATION" and second_refused
          and r1["admitted"] is True and n_exec == 1 and chain_ok)
    return ("H-01 one authorization admits exactly one execution", ok,
            f"second_compilation_refused={second_refused}, executions={n_exec}, verify={chain_ok}")


def h02_subject_substitution_blocked():
    """H-02. A commitment compiled for one subject must not be admitted under another."""
    h = Harness()
    now = time.time()
    action = {"subject_id": "subject-A", "action_class": "data.read", "target": "crm"}
    cc = h.c7.compile(action, now, permit_event_id=_dummy_permit(h, action, "subject-A"))
    r = h.present(cc, now, "subject-B", action)
    logged_b = any(e["event.type"] == "EXECUTION_AUTHORIZED" and e["event.subject_id"] == "subject-B"
                   for e in h.c5.events)
    ok = (r["admitted"] is False and r["block_reason"] == "CC_SUBJECT_MISMATCH" and not logged_b)
    return ("H-02 subject substitution blocked", ok, f"reason={r.get('block_reason')}")


def h02b_operation_substitution_blocked():
    """H-02, second half. The operation presented must be the operation authorized."""
    h = Harness()
    now = time.time()
    action = {"subject_id": "cs-agent-01", "action_class": "data.read", "target": "crm"}
    mutated = {"subject_id": "cs-agent-01", "action_class": "data.read", "target": "billing"}
    cc = h.c7.compile(action, now, permit_event_id=_dummy_permit(h, action))
    r = h.present(cc, now, "cs-agent-01", mutated)
    ok = r["admitted"] is False and r["block_reason"] == "CC_OPERATION_MISMATCH"
    return ("H-02b mutated operation blocked", ok, f"reason={r.get('block_reason')}")


def h03_content_addressed_id():
    """H-03. cc.id must be the content address of the commitment, and a commitment whose
    identifier does not match its content must be refused at the boundary."""
    h = Harness()
    now = time.time()
    action = {"subject_id": "cs-agent-01", "action_class": "data.read", "target": "crm"}
    pid = _dummy_permit(h, action)
    a = h.c7.compile(action, now, permit_event_id=pid)
    b = h.c7.compile(action, now, permit_event_id=pid)
    deterministic = a["cc.id"] == b["cc.id"]

    # The forged commitment is re-signed with the demo key. Signing over a tampered
    # cc.id would otherwise trip CC_SIGNATURE_INVALID first and leave the content-address
    # check as dead code — which is the defect class this scenario exists to rule out.
    forged = dict(a)
    forged["cc.id"] = "cc-" + "0" * 64
    forged["signature"] = hmac.new(
        _CC_KEY, _canon({k: v for k, v in forged.items() if k != "signature"}).encode(),
        hashlib.sha256,
    ).hexdigest()
    r = h.present(forged, now, "cs-agent-01", action)
    refused = r["admitted"] is False and r["block_reason"] == "CC_ID_NOT_CONTENT_ADDRESSED"

    ok = deterministic and refused
    return ("H-03 cc.id is content-addressed and checked", ok,
            f"deterministic={deterministic}, resigned_forged_id_refused={refused} "
            f"({r.get('block_reason')})")


def h04_double_authorization_detected():
    """H-04. A log containing two executions from one authorization must fail
    verification. The record is built by hand — this asserts on the verifier, not on the
    enforcement path, which h01 already covers."""
    h = Harness()
    action = {"subject_id": "cs-agent-01", "action_class": "data.export", "target": "billing"}
    p = h.c5.emit("PERMIT", "C2", "cs-agent-01", **{
        "event.action_spec": action, "event.decision_basis": "PERMIT_WITH_AUTHORIZATION",
        "event.auth_id": "auth-forged"})["event.id"]
    for cc_id in ("cc-aaa", "cc-bbb"):
        h.c5.emit("CC_COMPILED", "C7", "cs-agent-01", **{
            "event.cc_id": cc_id, "event.permit_event_id": p, "event.action_spec": action})
        h.c5.emit("EXECUTION_AUTHORIZED", "C6", "cs-agent-01", **{
            "event.cc_id": cc_id, "event.permit_event_id": p,
            "event.action_spec": action, "event.auth_id": "auth-forged"})

    chain_ok, _ = h.c5.verify_chain()
    full_ok, msg = h.c5.verify()
    ok = chain_ok and not full_ok
    return ("H-04 verifier rejects a double-authorization log", ok,
            f"chain_intact={chain_ok}, full_verify={full_ok} ({msg})")


def h04b_orphan_execution_detected():
    """H-04. An execution citing a commitment that was never compiled must be caught."""
    h = Harness()
    h.c5.emit("EXECUTION_AUTHORIZED", "C6", "cs-agent-01", **{
        "event.cc_id": "cc-never-compiled", "event.action_spec": {}})
    chain_ok, _ = h.c5.verify_chain()
    full_ok, msg = h.c5.verify()
    ok = chain_ok and not full_ok
    return ("H-04b verifier rejects an orphan execution", ok,
            f"chain_intact={chain_ok}, full_verify={full_ok} ({msg})")


ALL = [
    positive_path,
    nt001_non_cc_blocked,
    nt002_expired_cc_blocked,
    nt003_replay_blocked,
    nt004_unregistered_context_blocked,
    governed_exception,
    h01_one_authorization_one_execution,
    h02_subject_substitution_blocked,
    h02b_operation_substitution_blocked,
    h03_content_addressed_id,
    h04_double_authorization_detected,
    h04b_orphan_execution_detected,
]

ADVERSARIAL = ALL[6:]
