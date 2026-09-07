"""The shared redemption authority — CROA Part II §4.8.

§4.8 is unusually specific about how single-use is to be implemented, because the
obvious implementation is wrong:

    "The single-use guarantee MUST NOT be implemented as a query-then-act check
    (e.g., 'query C5 for prior redemption, then release'): that is a
    time-of-check-to-time-of-use race. C6 MUST perform redemption as a single
    linearizable compare-and-swap against one authoritative redemption registry."

Two consequences the previous harness did not implement.

**One registry, not one per instance.** §4.8: "a per-gateway-local redemption record
is non-conformant wherever more than one instance can admit operations for the same
governed system." Before this module, each ExecutionFirewall carried its own
`redeemed` set, so two firewalls admitted the same ECC twice. The firewall now holds
no redemption state at all; it holds a reference to a registry.

**One claim, not two.** §4.8: when an ECC carries `ecc.auth_ref`, C6 MUST redeem the
referenced `auth_id` "in the same atomic compare-and-swap that redeems `ecc.id`".
Claiming the ECC and then claiming the authorization is two operations, and a crash
or a race between them leaves an authorization spent against no execution, or an
execution admitted against a spent authorization. `claim()` therefore takes a *set* of
keys and is all-or-nothing over the whole set.

**What this is not.** The redemption authority is distinct from the C5 evidence path.
§4.8: "Replication lag in the C5 evidence path (Appendix R, Inv. 5) MUST NOT open a
redemption window: the linearizable redemption authority is distinct from, and MUST
commit ahead of, asynchronous evidence materialization." The Appendix R write-ahead
log lives in `mrh/wal.py` and answers a different question. Conflating the two is the
specific error §4.8 warns against.
"""
import json
import os
import threading

try:                                  # POSIX
    import fcntl
    _HAVE_FLOCK = True
except ImportError:                   # Windows
    fcntl = None
    _HAVE_FLOCK = False


class ClaimResult(object):
    """Outcome of one atomic claim.

    `conflict` names the *role* whose key was already spent ("ecc" or "auth"), which is
    what C6 needs to choose between ECC_ALREADY_REDEEMED and
    AUTHORIZATION_ALREADY_REDEEMED (§4.7.1, §4.8).
    """

    __slots__ = ("granted", "conflict", "conflict_key")

    def __init__(self, granted, conflict=None, conflict_key=None):
        self.granted = granted
        self.conflict = conflict
        self.conflict_key = conflict_key

    def __repr__(self):
        if self.granted:
            return "<ClaimResult granted>"
        return "<ClaimResult refused: %s=%s already redeemed>" % (self.conflict, self.conflict_key)


class RedemptionRegistry(object):
    """Interface. One authoritative instance is shared by every C6 in a governance domain.

    An implementation MUST make `claim` linearizable: for any set of concurrent calls
    whose key sets intersect, at most one may return granted. `bounded_count` supports
    the `N`-use redemption policy §4.8 allows for authorizations; the default of 1 is
    the single-use case.
    """

    def claim(self, keys, bounded_count=None):
        """Atomically claim every key in `keys` (role -> identifier), or none of them."""
        raise NotImplementedError

    def is_spent(self, key):
        """Advisory read. Stale the moment it returns; never gate a release on it."""
        raise NotImplementedError

    def count(self):
        raise NotImplementedError


class InProcessRegistry(RedemptionRegistry):
    """Single-process registry guarded by a mutex.

    Conformant for a deployment in which exactly one process can admit operations for a
    governed system — DM-1 with a single C6, and this demonstrator. It is **not**
    conformant for an HA C6 cluster, a horizontally scaled gateway, or a sidecar mesh
    (§4.8, §19.4, §21, §22.3): those need a registry shared across processes, which is
    what `FileLockRegistry` and `ConditionalWriteRegistry` provide.
    """

    kind = "in-process"
    shared_across_processes = False

    def __init__(self, bounded_count=None):
        self._lock = threading.Lock()
        self._spent = {}                      # key -> times claimed
        self._default_bound = bounded_count or {}

    def claim(self, keys, bounded_count=None):
        bounds = dict(self._default_bound)
        bounds.update(bounded_count or {})
        with self._lock:
            for role, key in keys.items():
                limit = bounds.get(role, 1)
                if self._spent.get(key, 0) >= limit:
                    return ClaimResult(False, role, key)
            for key in keys.values():         # only now, and all of them
                self._spent[key] = self._spent.get(key, 0) + 1
            return ClaimResult(True)

    def is_spent(self, key):
        with self._lock:
            return self._spent.get(key, 0) > 0

    def count(self):
        with self._lock:
            return len(self._spent)


class FileLockRegistry(RedemptionRegistry):
    """Registry shared across processes on one host, serialized by an advisory file lock.

    This is the smallest honest demonstration of the §4.8 contract that runs with no
    server: the lock is held across the read, the test and the write, so the whole
    multi-key claim is one critical section rather than a check followed by an act.
    Two processes racing on the same `ecc.id` produce exactly one grant.

    It is a demonstrator, not a production registry: an advisory lock binds one host and
    one filesystem, and it is not a substitute for a replicated store in a multi-host
    deployment. For that, see `ConditionalWriteRegistry`.
    """

    kind = "file-lock"
    shared_across_processes = True

    def __init__(self, path, bounded_count=None):
        if not _HAVE_FLOCK:
            raise RuntimeError(
                "FileLockRegistry needs fcntl (POSIX). On Windows, use "
                "ConditionalWriteRegistry with a store that offers a conditional write.")
        self.path = str(path)
        self._default_bound = bounded_count or {}
        if not os.path.exists(self.path):
            with open(self.path, "a"):
                pass

    def _read(self, fh):
        fh.seek(0)
        raw = fh.read()
        return json.loads(raw) if raw.strip() else {}

    def _write(self, fh, state):
        fh.seek(0)
        fh.truncate()
        fh.write(json.dumps(state, sort_keys=True))
        fh.flush()
        os.fsync(fh.fileno())             # the claim must survive a crash

    def claim(self, keys, bounded_count=None):
        bounds = dict(self._default_bound)
        bounds.update(bounded_count or {})
        with open(self.path, "r+") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                state = self._read(fh)
                for role, key in keys.items():
                    if state.get(key, 0) >= bounds.get(role, 1):
                        return ClaimResult(False, role, key)
                for key in keys.values():
                    state[key] = state.get(key, 0) + 1
                self._write(fh, state)
                return ClaimResult(True)
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

    def is_spent(self, key):
        with open(self.path, "r+") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_SH)
            try:
                return self._read(fh).get(key, 0) > 0
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

    def count(self):
        with open(self.path, "r+") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_SH)
            try:
                return len(self._read(fh))
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


class ConditionalWriteRegistry(RedemptionRegistry):
    """Registry backed by a store that offers an atomic conditional write.

    This is the shape a real multi-host deployment uses. The backend must implement one
    method:

        put_if_absent(key, value) -> bool     # True iff this call created the key

    which every candidate store already provides:

        etcd       Txn().If(Compare(Version(key), "=", 0)).Then(Put(key, v))
        DynamoDB   PutItem with ConditionExpression="attribute_not_exists(pk)"
        Postgres   INSERT ... ON CONFLICT DO NOTHING, checking rowcount
        Redis      SET key value NX
        Spanner    a read-write transaction with a read of the key in it

    Multi-key atomicity. A store with real multi-key transactions (etcd, Postgres,
    Spanner, DynamoDB TransactWriteItems) SHOULD claim the whole key set in one
    transaction; pass `transactional=True` and implement `put_all_if_absent(items)`.
    Where the store offers only single-key conditional writes, this class claims in a
    deterministic order and releases what it took on conflict. That rollback window can
    refuse a claim that would otherwise have been granted -- it fails deny, never
    permit -- but it is a weaker guarantee than §4.8 asks for, and a deployment relying
    on it should say so in its conformance evidence.
    """

    kind = "conditional-write"
    shared_across_processes = True

    def __init__(self, backend, transactional=False):
        self.backend = backend
        self.transactional = transactional

    def claim(self, keys, bounded_count=None):
        if bounded_count:
            raise NotImplementedError(
                "bounded-count redemption needs a counter with an atomic increment; "
                "model it in the backend rather than here")
        ordered = sorted(keys.items(), key=lambda kv: kv[1])

        if self.transactional:
            ok = self.backend.put_all_if_absent([k for _, k in ordered])
            return ClaimResult(True) if ok else ClaimResult(False, ordered[0][0], ordered[0][1])

        taken = []
        for role, key in ordered:
            if self.backend.put_if_absent(key, "1"):
                taken.append(key)
                continue
            for k in taken:                       # give back what we took
                self.backend.delete(k)
            return ClaimResult(False, role, key)
        return ClaimResult(True)

    def is_spent(self, key):
        return self.backend.exists(key)

    def count(self):
        return self.backend.count()
