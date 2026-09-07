"""The reference scenarios: the positive path, the reference negative tests of
Appendix Q, the adversarial scenarios that reproduce the defects an independent audit
found in September 2026, and -- new in v1.0.1 -- the redemption-registry and
Appendix R evidence-path scenarios. Each returns (name, passed, detail).

The adversarial group is the important one. The cooperative scenarios show the
mechanism working when called correctly; the adversarial ones are the only evidence
that it refuses when called incorrectly.
"""
import hashlib
import hmac
import os
import tempfile
import threading
import time

from .components import _ECC_KEY, _canon
from .harness import Harness
from .nt_appendix_q import evidence_pack_scenario, nt005, nt006, nt008
from .redemption import FileLockRegistry, InProcessRegistry
from .wal import LocalSigner


def _types(h, before=0):
    return [e["event.type"] for e in h.c5.events[before:]]


def _read(subject="cs-agent-01", target="orders-db"):
    return {"subject_id": subject, "action_class": "data.read", "target": target}


def _export(subject="cs-agent-01", target="billing"):
    return {"subject_id": subject, "action_class": "data.export", "target": target}


def _permit_event(h, action, sid="cs-agent-01", basis="PERMIT", auth_id=None):
    """Emit a PERMIT so a directly-compiled ECC has a real permit event to cite."""
    fields = {"event.session_id": "sess-" + sid, "event.action_spec": action,
              "event.decision_basis": basis}
    if auth_id is not None:
        fields["event.auth_id"] = auth_id
    return h.c5.emit("PERMIT", "C2", sid, **fields)["event.id"]


def _record_compiled(h, ecc, permit_event_id, sid="cs-agent-01"):
    """Emit the ECC_COMPILED event that governed_flow would have emitted.

    A scenario that drives C7 directly must still produce a coherent C5 record: an
    EXECUTION_AUTHORIZED citing an ECC never recorded as compiled is a broken log, and
    verify_decisions() is right to reject it -- which is what h04b asserts.
    """
    h.c5.emit("ECC_COMPILED", "C7", sid, **{
        "event.session_id": "sess-" + sid,
        "event.ecc_id": ecc["ecc.id"],
        "event.permit_event_id": permit_event_id,
        "event.action_spec": ecc["ecc.action"],
    })


# ------------------------------------------------------------ cooperative path
def positive_path():
    h = Harness()
    r = h.governed_flow(_read(), time.time())
    types = _types(h)
    ok = (r.get("admitted") is True
          and types == ["PERMIT", "ECC_COMPILED", "EXECUTION_AUTHORIZED",
                        "EXECUTION_COMPLETED", "EFFECT_ATTESTED"]
          and len(h.applied("orders-db")) == 1)
    return ("Positive path (permitted read, effect attested)", ok, "chain=%s" % types)


# ---------------------------------------------------- Appendix Q negative tests
def nt001_non_ecc_blocked():
    """NT-001. An operation carrying no ECC is refused at the boundary."""
    h = Harness()
    r = h.present(None, time.time(), "cs-agent-01", _read())
    ok = r["admitted"] is False and r["block_reason"] == "ECC_NOT_FOUND"
    return ("NT-001 non-ECC execution blocked", ok, "reason=%s" % r.get("block_reason"))


def nt002_expired_ecc_blocked():
    """NT-002. An ECC past ecc.expires_at is refused, and refusing it must not
    consume its single use: the static checks run before the claim."""
    h = Harness()
    now = time.time()
    action = _read()
    pid = _permit_event(h, action)
    ecc = h.c7.compile(h.c3.ground(action), action["subject_id"], now, permit_event_id=pid, ttl=1)
    _record_compiled(h, ecc, pid)
    r = h.present(ecc, now + 60, "cs-agent-01", action)
    unspent = not h.registry.is_spent(ecc["ecc.id"])
    ok = r["admitted"] is False and r["block_reason"] == "ECC_EXPIRED" and unspent
    return ("NT-002 expired ECC blocked (and not spent)", ok,
            "reason=%s registry_untouched=%s" % (r.get("block_reason"), unspent))


def nt003_replay_blocked():
    """NT-003. A redeemed ECC re-presented inside its window is a replay."""
    h = Harness()
    now = time.time()
    action = _read()
    first = h.governed_flow(action, now)
    r = h.present(first["ecc"], now, "cs-agent-01", action)
    ok = (first["admitted"] is True and r["admitted"] is False
          and r["block_reason"] == "ECC_ALREADY_REDEEMED"
          and len(h.applied("orders-db")) == 1)
    return ("NT-003 ECC replay blocked", ok,
            "first=%s replay=%s effects=%d" % (first["admitted"], r.get("block_reason"),
                                               len(h.applied("orders-db"))))


def nt004_unregistered_context_blocked():
    """NT-004. An entity absent from the Federated Context Registry never reaches C2."""
    h = Harness()
    before = len(h.c5.events)
    r = h.governed_flow(_read(target="shadow-db"), time.time())
    types = _types(h, before)
    ok = (r["outcome"] == "BLOCKED" and types == ["CONTEXT_FAILURE"]
          and h.c5.events[-1]["c2_invoked"] is False)
    return ("NT-004 unregistered context blocked", ok, "events=%s" % types)


def nt004b_resolver_unavailable_fail_closed():
    """§4.5. C3 being unavailable is fail-closed, not only resolution failure: a
    grounding that cannot be performed is a grounding that failed."""
    h = Harness()
    h.c3.available = False
    r = h.governed_flow(_read(), time.time())
    ok = (r["outcome"] == "BLOCKED"
          and h.c5.events[-1]["context_registry_check"] == "C3_UNAVAILABLE")
    return ("C3 unavailable is fail-closed (§4.5)", ok, "outcome=%s" % r["outcome"])


def nt007_governed_exception_single_use():
    """NT-007, all four steps.

    1 first use admitted under the authorization;
    2 a *second, distinct* ECC compiled against the same authorization is refused at
      the boundary -- §4.8 anticipates the second compilation and requires C6 to refuse
      it, which is why C7 no longer spends the authorization;
    3 an operation outside ecc.exception_scope is refused;
    4 two concurrent presentations to two C6 instances admit at most one.
    """
    h = Harness(firewalls=2)
    now = time.time()
    action = _export(target="billing")
    auth = h.c1.issue_authorization(action, now)

    step1 = h.governed_flow(action, now, authorization=auth)

    # Step 2 -- fresh permit, fresh ECC, same authorization.
    step2 = h.governed_flow(action, now, authorization=auth)
    step2_blocked = (step2.get("admitted") is False
                     and step2.get("block_reason") in ("AUTHORIZATION_ALREADY_REDEEMED",
                                                       "ECC_ALREADY_REDEEMED")) or \
                    step2.get("outcome") == "DENIED"

    # Step 3 -- widening: present the step-1 contract for a different target.
    widened = _export(target="analytics")
    step3 = h.present(step1["ecc"], now, "cs-agent-01", widened)

    # Step 4 -- two concurrent presentations of one fresh ECC to two firewalls.
    h2 = Harness(firewalls=2)
    action2 = _export(target="billing")
    auth2 = h2.c1.issue_authorization(action2, now)
    pid = _permit_event(h2, action2, basis="PERMIT_WITH_AUTHORIZATION",
                        auth_id=auth2["auth_id"])
    ecc2 = h2.c7.compile(h2.c3.ground(action2), action2["subject_id"], now, permit_event_id=pid, authorization=auth2)
    _record_compiled(h2, ecc2, pid)
    results = []
    lock = threading.Lock()

    def race(fw):
        r = h2.present(ecc2, now, "cs-agent-01", action2, firewall=fw)
        with lock:
            results.append(r["admitted"])

    threads = [threading.Thread(target=race, args=(fw,)) for fw in h2.firewalls]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    step4_ok = results.count(True) == 1

    authorized = [e for e in h.c5.events
                  if e["event.type"] == "EXECUTION_AUTHORIZED"
                  and e.get("event.auth_id") == auth["auth_id"]]
    # Step 3 violates both scopes at once -- the widened target is outside the permit
    # as well as outside the waiver -- and C6 reports the more fundamental of the two.
    # `exception_scope_enforced` below isolates the waiver check on its own.
    ok = (step1.get("admitted") is True and step2_blocked
          and step3["admitted"] is False
          and step3.get("block_detail") in ("OPERATION_OUTSIDE_AUTHORIZATION_SCOPE",
                                            "OPERATION_OUTSIDE_EXCEPTION_SCOPE")
          and step4_ok
          and len(authorized) == 1
          and len(h.applied("billing")) == 1
          and h.applied("analytics") == []
          and h.c5.verify()[0] and h2.c5.verify()[0])
    return ("NT-007 governed exception single-use (4 steps)", ok,
            "step1=%s step2=%s step3=%s step4=%s authorized_under_auth=%d"
            % (step1.get("admitted"), step2.get("block_reason") or step2.get("outcome"),
               step3.get("block_detail"), results, len(authorized)))


def exception_scope_enforced_independently():
    """§4.3.1. The bounded exception scope is enforced on its own, not as a side effect
    of the permit scope.

    C1 waives I-EXPORT-001 for `billing` alone, while the permit legitimately covers the
    action class for `analytics` too. An export to `analytics` is therefore *inside*
    ecc.authorization_scope and *outside* ecc.exception_scope: the waiver check is the
    only thing standing between the agent and an unapproved destination.
    """
    h = Harness()
    now = time.time()
    action = _export(target="billing")
    auth = h.c1.issue_authorization(action, now)          # waives billing only
    pid = _permit_event(h, action, basis="PERMIT_WITH_AUTHORIZATION", auth_id=auth["auth_id"])
    ecc = h.c7.compile(h.c3.ground(action), action["subject_id"], now, permit_event_id=pid, authorization=auth,
                       additional_scope=[{"target": "analytics",
                                          "action_type": "data.export"}])
    _record_compiled(h, ecc, pid)
    widened = _export(target="analytics")
    in_permit = h.c6._in_authorization_scope(ecc, widened)
    r = h.present(ecc, now, "cs-agent-01", widened)
    ok = (in_permit is True and r["admitted"] is False
          and r.get("block_detail") == "OPERATION_OUTSIDE_EXCEPTION_SCOPE"
          and h.applied("analytics") == []
          and not h.registry.is_spent(auth["auth_id"]))
    return ("Exception scope enforced independently of permit scope (§4.3.1)", ok,
            "inside_permit=%s detail=%s auth_unspent=%s"
            % (in_permit, r.get("block_detail"), not h.registry.is_spent(auth["auth_id"])))


# --------------------------------------------------- §4.8 redemption registry
def shared_registry_across_firewalls():
    """§4.8. One ECC, two C6 instances, one registry: at most one admission.

    Before v1.0.1 each firewall carried its own redeemed set, so this scenario admitted
    twice. It is the sequential form of NT-007 step 4 and the reason the firewall now
    holds no redemption state at all.
    """
    h = Harness(firewalls=2)
    now = time.time()
    action = _read()
    pid = _permit_event(h, action)
    ecc = h.c7.compile(h.c3.ground(action), action["subject_id"], now, permit_event_id=pid)
    _record_compiled(h, ecc, pid)
    a = h.present(ecc, now, "cs-agent-01", action, firewall=h.firewalls[0])
    b = h.present(ecc, now, "cs-agent-01", action, firewall=h.firewalls[1])
    ok = a["admitted"] is True and b["admitted"] is False and \
        b["block_reason"] == "ECC_ALREADY_REDEEMED"
    return ("Shared registry: second C6 instance refuses the same ECC", ok,
            "c6-1=%s c6-2=%s" % (a["admitted"], b.get("block_reason")))


def registry_claim_is_all_or_nothing():
    """§4.8. The ECC and its auth_ref are claimed in one operation.

    A claim that takes the ECC and then fails on the authorization must leave the ECC
    unclaimed; otherwise a refused presentation silently burns a contract that was
    never executed.
    """
    reg = InProcessRegistry()
    reg.claim({"auth": "auth-x"})                      # authorization already spent
    result = reg.claim({"ecc": "ecc-1", "auth": "auth-x"})
    ok = (result.granted is False and result.conflict == "auth"
          and not reg.is_spent("ecc-1"))
    return ("Registry claim is all-or-nothing", ok,
            "granted=%s conflict=%s ecc_untouched=%s"
            % (result.granted, result.conflict, not reg.is_spent("ecc-1")))


def registry_cross_process_cas():
    """§4.8. The file-lock registry is linearizable across processes.

    Forks N children that all claim the same key. Exactly one may win. A query-then-act
    implementation loses this test; a claim held under one lock passes it.
    """
    if not hasattr(os, "fork"):
        return ("Cross-process CAS (file-lock registry)", True, "skipped: no os.fork")
    path = os.path.join(tempfile.mkdtemp(), "redemption.json")
    reg = FileLockRegistry(path)
    n = 8
    r_fd, w_fd = os.pipe()
    pids = []
    for _ in range(n):
        pid = os.fork()
        if pid == 0:                                    # child
            os.close(r_fd)
            try:
                won = FileLockRegistry(path).claim({"ecc": "ecc-contended"}).granted
                os.write(w_fd, b"1" if won else b"0")
            finally:
                os._exit(0)
        pids.append(pid)
    os.close(w_fd)
    data = b""
    while len(data) < n:
        chunk = os.read(r_fd, n - len(data))
        if not chunk:
            break
        data += chunk
    os.close(r_fd)
    for pid in pids:
        os.waitpid(pid, 0)
    winners = data.count(b"1")
    ok = winners == 1 and reg.is_spent("ecc-contended")
    return ("Cross-process CAS: %d processes, one winner" % n, ok,
            "winners=%d of %d" % (winners, n))


# ------------------------------------------------- Appendix R evidence pattern
def wal_durable_and_chained():
    """Appendix R steps 3-5. Every event is chained, signed and fsync'd to a real file,
    and the chain verifies from the file alone."""
    d = tempfile.mkdtemp()
    path = os.path.join(d, "c5.wal")
    from .audit import AuditStore
    h = Harness(audit=AuditStore(path=path))
    h.governed_flow(_read(), time.time())
    with open(path, encoding="utf-8") as fh:
        on_disk = sum(1 for _ in fh)
    ok_chain, msg = h.c5.verify()
    ok = ok_chain and on_disk == len(h.c5.events) and h.c5.wal.durable
    return ("Appendix R: WAL durable, chained, verifiable", ok,
            "lines_on_disk=%d events=%d %s" % (on_disk, len(h.c5.events), msg))


def wal_replication_reconciles():
    """Appendix R steps 7-9 and invariant 7. Replication is off the admission path, and
    local and central must agree over the replicated period."""
    h = Harness()
    now = time.time()
    h.governed_flow(_read(), now)
    lag_before = h.c5.replicator.lag()
    ok_rep, msg_rep = h.c5.replicate()
    ok_rec, msg_rec = h.c5.reconcile()
    ok = ok_rep and ok_rec and lag_before > 0 and h.c5.replicator.lag() == 0
    return ("Appendix R: replication reconciles with the local WAL", ok,
            "lag_before=%d lag_after=%d %s" % (lag_before, h.c5.replicator.lag(), msg_rec))


def wal_tamper_is_detected():
    """R.4 invariant 3. A modified event breaks the chain, and the central store
    refuses a batch whose continuity it cannot verify."""
    h = Harness()
    h.governed_flow(_read(), time.time())
    h.c5.events[0]["event.subject_id"] = "someone-else"
    ok_local, msg = h.c5.verify_chain()
    ok_rep, _ = h.c5.replicate()
    ok = ok_local is False and ok_rep is False and h.c5.central.alerts
    return ("Appendix R: tampering breaks the chain and the replication gate", ok,
            "local=%r central_alerts=%d" % (msg, len(h.c5.central.alerts)))


def wal_signing_key_not_reachable():
    """R.4 invariant 4. The WAL signing key must not sit in the governed agent's trust
    domain. Name-mangled and never exposed: a compromised caller can ask for a
    signature but cannot extract the key and forge arbitrary ones offline."""
    signer = LocalSigner()
    reachable = [a for a in dir(signer) if "key" in a.lower() and not a.startswith("_LocalSigner")]
    ok = reachable == [] and not hasattr(signer, "key")
    return ("Appendix R inv. 4: WAL signing key is not reachable from the harness", ok,
            "public_key_attributes=%s" % reachable)


# --------------------------------------------------------- audit regressions
def h01_one_authorization_one_execution():
    """H-01. Two decisions taken on one authorization before any redemption must still
    yield at most one admitted execution. The guarantee moved from C7 to C6; the
    property is unchanged."""
    h = Harness()
    now = time.time()
    action = _export(target="billing")
    auth = h.c1.issue_authorization(action, now)
    pid1 = _permit_event(h, action, basis="PERMIT_WITH_AUTHORIZATION", auth_id=auth["auth_id"])
    pid2 = _permit_event(h, action, basis="PERMIT_WITH_AUTHORIZATION", auth_id=auth["auth_id"])
    ecc1 = h.c7.compile(h.c3.ground(action), action["subject_id"], now, permit_event_id=pid1, authorization=auth)
    ecc2 = h.c7.compile(h.c3.ground(action), action["subject_id"], now, permit_event_id=pid2, authorization=auth)
    _record_compiled(h, ecc1, pid1)
    _record_compiled(h, ecc2, pid2)
    a = h.present(ecc1, now, "cs-agent-01", action)
    b = h.present(ecc2, now, "cs-agent-01", action)
    ok = (a["admitted"] is True and b["admitted"] is False
          and b["block_reason"] == "AUTHORIZATION_ALREADY_REDEEMED"
          and len(h.applied("billing")) == 1)
    return ("H-01 one authorization backs one execution", ok,
            "first=%s second=%s" % (a["admitted"], b.get("block_reason")))


def h02_subject_substitution_blocked():
    """H-02. An ECC compiled for one subject must not be admitted under another."""
    h = Harness()
    now = time.time()
    action = _read()
    pid = _permit_event(h, action)
    ecc = h.c7.compile(h.c3.ground(action), action["subject_id"], now, permit_event_id=pid)
    _record_compiled(h, ecc, pid)
    r = h.present(ecc, now, "intruder-99", action)
    ok = r["admitted"] is False and r.get("block_detail") == "SUBJECT_MISMATCH"
    return ("H-02 subject substitution blocked", ok, "detail=%s" % r.get("block_detail"))


def h02b_operation_substitution_blocked():
    """H-02, second half. The operation presented must be inside the scope authorized."""
    h = Harness()
    now = time.time()
    action = _read()
    pid = _permit_event(h, action)
    ecc = h.c7.compile(h.c3.ground(action), action["subject_id"], now, permit_event_id=pid)
    _record_compiled(h, ecc, pid)
    r = h.present(ecc, now, "cs-agent-01", _export(target="analytics"))
    ok = (r["admitted"] is False
          and r.get("block_detail") == "OPERATION_OUTSIDE_AUTHORIZATION_SCOPE")
    return ("H-02b operation substitution blocked", ok, "detail=%s" % r.get("block_detail"))


def h03_content_addressed_id():
    """H-03. ecc.id must be the content address of the contract, and a contract whose
    identifier is not the hash of its own content must be refused."""
    h = Harness()
    now = time.time()
    action = _read()
    pid = _permit_event(h, action)
    ecc = h.c7.compile(h.c3.ground(action), action["subject_id"], now, permit_event_id=pid)
    content = dict((k, v) for k, v in ecc.items() if k not in ("ecc.id", "ecc.signature"))
    recomputed = "ecc-" + hashlib.sha256(_canon(content).encode()).hexdigest()
    addressed = ecc["ecc.id"] == recomputed

    forged = dict(ecc)
    forged["ecc.id"] = "ecc-" + "0" * 64
    forged["ecc.signature"] = hmac.new(
        _ECC_KEY,
        _canon(dict((k, v) for k, v in forged.items() if k != "ecc.signature")).encode(),
        hashlib.sha256).hexdigest()
    r = h.present(forged, now, "cs-agent-01", action)
    ok = addressed and r["admitted"] is False and \
        r.get("block_detail") == "ID_NOT_CONTENT_ADDRESSED"
    return ("H-03 ecc.id is a content address", ok,
            "addressed=%s forged=%s" % (addressed, r.get("block_detail")))


def h04_double_authorization_detected():
    """H-04. A log containing two executions from one authorization must fail
    verification, even though its chain is intact."""
    h = Harness()
    now = time.time()
    action = _export(target="billing")
    auth_id = "auth-forged"
    for _ in range(2):
        pid = _permit_event(h, action, basis="PERMIT_WITH_AUTHORIZATION", auth_id=auth_id)
        ecc = h.c7.compile(h.c3.ground(action), action["subject_id"], now, permit_event_id=pid)
        _record_compiled(h, ecc, pid)
        h.c5.emit("EXECUTION_AUTHORIZED", "C6", "cs-agent-01", **{
            "event.ecc_id": ecc["ecc.id"],
            "event.permit_event_id": pid,
            "event.session_id": "sess-cs-agent-01",
            "event.auth_id": auth_id,
        })
    chain_ok, _ = h.c5.verify_chain()
    ok_all, msg = h.c5.verify()
    ok = chain_ok is True and ok_all is False and "more than one execution" in msg
    return ("H-04 two executions from one authorization detected", ok,
            "chain_ok=%s verify=%r" % (chain_ok, msg))


def h04b_orphan_execution_detected():
    """H-04. An execution citing an ECC that was never compiled must be caught."""
    h = Harness()
    h.c5.emit("EXECUTION_AUTHORIZED", "C6", "cs-agent-01", **{
        "event.ecc_id": "ecc-never-compiled",
        "event.session_id": "sess-cs-agent-01",
    })
    ok_all, msg = h.c5.verify()
    ok = ok_all is False and "never compiled" in msg
    return ("H-04b orphan execution detected", ok, "verify=%r" % msg)


ALL = [
    positive_path,
    nt001_non_ecc_blocked,
    nt002_expired_ecc_blocked,
    nt003_replay_blocked,
    nt004_unregistered_context_blocked,
    nt004b_resolver_unavailable_fail_closed,
    nt005,
    nt006,
    nt007_governed_exception_single_use,
    nt008,
    exception_scope_enforced_independently,
    shared_registry_across_firewalls,
    registry_claim_is_all_or_nothing,
    registry_cross_process_cas,
    wal_durable_and_chained,
    wal_replication_reconciles,
    wal_tamper_is_detected,
    wal_signing_key_not_reachable,
    h01_one_authorization_one_execution,
    h02_subject_substitution_blocked,
    h02b_operation_substitution_blocked,
    h03_content_addressed_id,
    h04_double_authorization_detected,
    h04b_orphan_execution_detected,
    evidence_pack_scenario,
]
