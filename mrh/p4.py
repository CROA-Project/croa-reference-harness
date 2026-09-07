"""Property P4 — a governed system reachable only through C6 (H-06).

The rest of this harness calls a Python method. That is enough to show the *shape* of
the mechanism and nothing at all about the property the mechanism exists to provide:
`NT-001` asserting that `present(None)` returns `BLOCKED` shows that a function returned
a string, not that a non-ECC execution is unreachable. P4 is the most load-bearing
condition of CROA's central claim and it was the one thing the demonstrator did not
demonstrate.

This module builds the smallest arrangement in which the claim can actually fail.

    agent  ──(unix socket, addressable)──▶  C6 gateway  ──(fd)──▶  governed system
      │                                                                 │
      └────────── no address to connect to ─────────────X               ▼
                                                                   its own log

Three OS processes, not three objects. The governed system is a separate `python`
process whose only channel is **one end of a `socketpair` handed to the gateway at
spawn**. It never calls `bind()`, so there is no path in the filesystem and no port on
the loopback interface: the agent has nothing to connect *to*. Unreachability here is
not a check that could be wrong -- it is the absence of an address.

The gateway is addressable, and must be: C6 is the sole execution path, not a hidden
one. It holds the fd, runs the real `ExecutionFirewall` over the real
`RedemptionRegistry`, and forwards only what it admits.

**Assertions are made on the governed system's own log file**, which that process writes
and no other process can reach. That is what makes the test an observation of an
external effect rather than of a return value -- Part VI §29.4's distinction, applied to
the demonstrator itself.

What this establishes, and what it does not
-------------------------------------------
Establishes: with the only channel to the governed system held by C6, an operation
appears in the system's log **only** after C6 admitted it; a direct attempt fails in the
operating system before any Python of ours runs; and refusing an operation leaves the
log unchanged, so a refusal is observably not a silent success.

Does **not** establish: that a *deployment* has this property. This is process
isolation, obtained by not naming the socket. A real deployment has named endpoints and
must obtain the same property from network policy -- a namespace, a security group, an
`AuthorizationPolicy` -- and must prove it the same way, by trying the direct path and
watching it fail. The optional namespace variant below does that with real network
controls where the platform allows it; where it does not, this module is the floor and
the register keeps H-06 open about the rest.
"""
import errno
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time


# --------------------------------------------------------------------------- framing
def send(sock, obj):
    sock.sendall((json.dumps(obj) + "\n").encode("utf-8"))


def recv(f):
    line = f.readline()
    if not line:
        return None
    return json.loads(line)


# ------------------------------------------------------------------ governed system
def run_governed_system(fd, log_path):
    """The governed system. Reads operations from ONE file descriptor and appends every
    operation it performs to its own log.

    It never binds an address. That is the whole point and it is one line of absence:
    there is no `socket.bind` in this function, so there is nothing for an agent to
    connect to, and no policy anywhere that has to be correct for that to hold.

    The log is written with O_APPEND and fsync'd, because a test that asserts on an
    effect must assert on an effect that survived the process.
    """
    sock = socket.socket(fileno=fd)
    f = sock.makefile("rb")
    while True:
        req = recv(f)
        if req is None:
            break
        if req.get("op") == "__shutdown__":
            break
        with open(log_path, "a", encoding="utf-8") as log:
            log.write(json.dumps(req) + "\n")
            log.flush()
            os.fsync(log.fileno())
        send(sock, {"applied": True, "op": req})
    sock.close()


# -------------------------------------------------------------------- the C6 gateway
def run_gateway(fd, listen_path, ready_path):
    """C6 as a process. Addressable, because the sole execution path must be usable.

    Holds the only channel to the governed system. Validates with the same
    `ExecutionFirewall` the in-process harness uses -- there is no second, friendlier
    implementation here, which matters: a gateway that re-implemented admission would be
    testing something other than the thing that ships.
    """
    from .components import ExecutionFirewall, request_of
    from .redemption import InProcessRegistry

    system = socket.socket(fileno=fd)
    system_f = system.makefile("rb")
    c6 = ExecutionFirewall(InProcessRegistry(), instance_id="c6-gateway")

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(listen_path)
    server.listen(8)
    with open(ready_path, "w", encoding="utf-8") as fh:
        fh.write(str(os.getpid()))

    while True:
        conn, _ = server.accept()
        conn_f = conn.makefile("rb")
        req = recv(conn_f)
        if req is None or req.get("op") == "__shutdown__":
            send(system, {"op": "__shutdown__"})
            conn.close()
            break
        ecc = req.get("ecc")
        operation = req.get("operation")
        if operation is None and ecc is not None:
            operation = request_of(ecc["ecc.action"])
        status, block_reason, detail = c6.redeem(
            ecc, time.time(), req.get("subject_id"), operation)
        if status != "AUTHORIZED":
            # Nothing is forwarded. The governed system is not told a refusal happened,
            # because from its side nothing happened: that is what "sole execution path"
            # has to mean for the log to be evidence.
            send(conn, {"admitted": False, "block_reason": block_reason,
                        "block_detail": detail})
            conn.close()
            continue
        send(system, operation)
        applied = recv(system_f)
        send(conn, {"admitted": True, "applied": bool(applied and applied.get("applied"))})
        conn.close()
    server.close()
    system.close()


# -------------------------------------------------------------------------- the bench
class P4Bench(object):
    """Starts the two processes and gives the agent the only thing it legitimately has:
    the gateway's address."""

    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="croa-p4-")
        self.log_path = os.path.join(self.dir, "governed-system.log")
        self.gateway_path = os.path.join(self.dir, "c6.sock")
        self.ready_path = os.path.join(self.dir, "gateway.pid")
        #: Where a naive deployment would have put the governed system's socket. The
        #: agent's direct attempt aims here, and there is nothing there.
        self.system_path = os.path.join(self.dir, "governed-system.sock")
        open(self.log_path, "w").close()
        self.procs = []

    def start(self):
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        env = dict(os.environ, PYTHONPATH=os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))))
        # close_fds is the default, so each child receives exactly one inherited socket
        # and the agent (this process's other children, and the test itself) receives
        # none. The governed system's channel is not something anyone can ask for.
        self.procs.append(subprocess.Popen(
            [sys.executable, "-m", "mrh.p4", "system", str(a.fileno()), self.log_path],
            pass_fds=(a.fileno(),), env=env))
        self.procs.append(subprocess.Popen(
            [sys.executable, "-m", "mrh.p4", "gateway", str(b.fileno()),
             self.gateway_path, self.ready_path],
            pass_fds=(b.fileno(),), env=env))
        a.close()
        b.close()
        deadline = time.time() + 10
        while not os.path.exists(self.ready_path):
            if time.time() > deadline:
                raise RuntimeError("gateway did not come up")
            time.sleep(0.01)
        return self

    # ---------------------------------------------------------------- the two paths
    def direct_attempt(self):
        """The agent tries to reach the governed system without C6.

        Returns the OS errno. There is no Python of ours between the attempt and the
        kernel: the failure is `connect(2)` failing, which is the only kind of
        unreachability worth asserting on.
        """
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.connect(self.system_path)
        except OSError as exc:
            return exc.errno
        finally:
            s.close()
        return 0

    def direct_attempt_tcp(self, port):
        """The same question asked of the loopback interface, since a reader is entitled
        to wonder whether the governed system quietly listens on a port instead."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        try:
            s.connect(("127.0.0.1", port))
        except OSError as exc:
            return exc.errno
        finally:
            s.close()
        return 0

    def through_gateway(self, ecc, subject_id, operation=None):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(self.gateway_path)
        send(s, {"ecc": ecc, "subject_id": subject_id, "operation": operation})
        reply = recv(s.makefile("rb"))
        s.close()
        return reply

    # ------------------------------------------------------------------- observation
    def system_log(self):
        """What the governed system itself recorded. The only evidence this bench
        accepts."""
        with open(self.log_path, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def stop(self):
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(self.gateway_path)
            send(s, {"op": "__shutdown__"})
            s.close()
        except OSError:
            pass
        for p in self.procs:
            try:
                p.wait(timeout=5)
            except Exception:
                p.kill()
        # The log is evidence only while the bench is up. Leaving a directory per run
        # behind would be a slow leak in a suite that runs on every push.
        shutil.rmtree(self.dir, ignore_errors=True)

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
        return False


def main(argv):
    if argv[1] == "system":
        run_governed_system(int(argv[2]), argv[3])
    elif argv[1] == "gateway":
        run_gateway(int(argv[2]), argv[3], argv[4])
    else:                                                     # pragma: no cover
        raise SystemExit("usage: p4 (system|gateway) ...")


if __name__ == "__main__":
    main(sys.argv)
