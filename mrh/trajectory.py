"""C4 — Invariant Monitor and trajectory analysis (Part II §4.6).

C4 is the architectural answer to the attack that no single-action check can see: a
sequence of individually permissible actions that walks the system to a state from which
a violation becomes reachable. §4.6 puts it plainly -- C4 "observes sequences, not only
individual actions".

Three things in this module are normative rather than convenient.

**Self-reported state is not evidence.** §4.6: "C4 MUST treat the governed agent's
self-reported state as unverified. State observations MUST come from independent
observation of governed systems, not from the governed agent's assertions about what it
has or has not done." So `observe()` is called by the harness on the *outcome* of a
decision, never by the agent.

**Unavailability is fail-deny.** §4.6: "When C4 is unavailable or unable to deliver
invariant state for a given governed action, C2 MUST default to issuing a deny decision
... implementations MUST NOT default to fail-permit behavior under C4 unavailability."

**A session starts empty.** §4.6.1: "No state, trajectory history, or invariant
observations from prior sessions MUST be carried into the new session's trajectory
analysis, even if the subject identity is the same." Carrying it over is how a
cross-session accumulation gets counted twice -- and the deliberate exception, TP-X, is
declared per invariant rather than assumed.
"""
import uuid


class C4Unavailable(Exception):
    """Raised when trajectory state cannot be produced. The caller must fail deny."""


class TrajectoryState(object):
    """The accumulated state of one cumulative invariant within one session."""

    __slots__ = ("id", "invariant_id", "session_id", "current_value", "alert_threshold",
                 "hard_limit", "alerted", "contributions")

    def __init__(self, invariant_id, session_id, alert_threshold, hard_limit):
        self.id = "traj-" + uuid.uuid4().hex[:12]
        self.invariant_id = invariant_id
        self.session_id = session_id
        self.current_value = 0
        self.alert_threshold = alert_threshold
        self.hard_limit = hard_limit
        self.alerted = False
        self.contributions = []          # (gar_id, increment) -- reconstructable from C5

    def snapshot(self):
        return {
            "trajectory_state_id": self.id,
            "invariant_id": self.invariant_id,
            "current_value": self.current_value,
            "alert_threshold": self.alert_threshold,
            "hard_limit": self.hard_limit,
        }


class InvariantMonitor(object):
    """C4.

    `available=False` models the outage §4.6 requires to fail deny. It is a field rather
    than an exception hook because an outage is a state a deployment is in, not an event
    it raises.
    """

    def __init__(self, registry, horizon=3, available=True):
        self.registry = registry
        self.horizon = horizon            # §4.6.2: enterprise-defined h, default 3
        self.available = available
        self.sessions = {}                # session_id -> {"history": [...], "states": {...}}

    # ------------------------------------------------------------------ session
    def _session(self, session_id):
        if session_id not in self.sessions:
            # §4.6.1: a fresh session history, carrying nothing across.
            self.sessions[session_id] = {"history": [], "states": {}}
        return self.sessions[session_id]

    def _state(self, session_id, invariant):
        sess = self._session(session_id)
        if invariant.id not in sess["states"]:
            agg = invariant.aggregate
            sess["states"][invariant.id] = TrajectoryState(
                invariant.id, session_id, agg["alert_threshold"], agg["hard_limit"])
        return sess["states"][invariant.id]

    # ------------------------------------------------------------- evaluation
    def assess(self, action, session_id):
        """Invariant state for one action, before C2 decides. Returns a dict.

        Carries `breach` when a cumulative invariant's hard limit would be crossed by
        this action, which C2 turns into a DENY.

        It does **not** raise the alert. The threshold is reached by an action that has
        *completed*, not by one being evaluated: Appendix Q's NT-006 sequence puts the
        TRAJECTORY_ALERT after the fifth PERMIT (items 13 then 14), and §4.6.2 step 3
        requires only that it be raised "before the next governed action in the session
        is evaluated". Raising it here instead would alert on a request that might still
        be denied -- reporting an approach to a limit that never happened.
        """
        if not self.available:
            # §4.6: C2 must fail deny, and the deny_reason must name C4 unavailability.
            raise C4Unavailable("C4 unavailable: invariant state cannot be delivered")

        result = {"at_risk": [], "breach": None, "alert": None, "states": {}}
        for inv in self.registry.trajectory_relevant():
            if inv.trajectory_profile in ("TP-C", "TP-X"):
                st = self._state(self._scope_key(inv, session_id, action), inv)
                inc = self._increment(inv, action)
                result["states"][inv.id] = st.snapshot()
                if inc == 0:
                    continue
                projected = st.current_value + inc
                if projected > st.hard_limit:  # the 6th request in NT-006
                    result["breach"] = {
                        "invariant_id": inv.id,
                        "trajectory_state_id": st.id,
                        "current_value": st.current_value,
                        "increment": inc,
                        "projected": projected,
                        "hard_limit": st.hard_limit,
                    }
                elif st.alerted:
                    result["at_risk"].append(inv.id)
        return result

    def _scope_key(self, invariant, session_id, action):
        """TP-C accumulates within a session; TP-X spans sessions for one subject.

        §4.6.3: TP-X is "a TP-C invariant whose window deliberately spans session
        boundaries for the same subject identity (low-and-slow)". Modelling it as a
        different accumulation key rather than a different algorithm keeps the two
        profiles honestly one mechanism with two windows.
        """
        if invariant.trajectory_profile == "TP-X":
            return "subject:" + action["subject_id"]
        return session_id

    def _increment(self, invariant, action):
        field = invariant.aggregate.get("field")
        value = action.get(field, 0) if field else 0
        if invariant.aggregate.get("function") == "distinct-count":
            return len(value) if isinstance(value, (list, set, tuple)) else int(value or 0)
        return int(value or 0)

    # -------------------------------------------------------------- recording
    def observe(self, action, session_id, decision, gar_id=None):
        """Record the outcome of a decision. Returns the state that just crossed its
        alert threshold, or None.

        Only an *executed* action accumulates.

        A denied action changes no state, so counting it would make the aggregate a
        record of what the agent asked for rather than of what happened -- and the agent
        would be able to drive the counter to its limit with requests that were all
        refused.
        """
        if not self.available:
            raise C4Unavailable("C4 unavailable")
        sess = self._session(session_id)
        sess["history"].append({"action": action, "decision": decision, "gar_id": gar_id})
        if decision not in ("PERMIT", "PERMIT_WITH_AUTHORIZATION"):
            return None
        marked = None
        for inv in self.registry.trajectory_relevant():
            if inv.trajectory_profile not in ("TP-C", "TP-X"):
                continue
            inc = self._increment(inv, action)
            if inc == 0:
                continue
            st = self._state(self._scope_key(inv, session_id, action), inv)
            st.current_value += inc
            st.contributions.append((gar_id, inc))
            if st.current_value >= st.alert_threshold and not st.alerted:
                st.alerted = True
                marked = st
        return marked

    def history(self, session_id):
        return self._session(session_id)["history"]

    def end_session(self, session_id, audit):
        """§4.6.1: transfer the complete session history to C5 before clearing it, and
        keep it if C5 cannot confirm receipt."""
        sess = self.sessions.get(session_id)
        if sess is None:
            return False
        audit.emit("TRAJECTORY_ALERT", "C4", "session-close", **{
            "event.session_id": session_id,
            "event.action_spec": [h["action"] for h in sess["history"]],
            "event.invariant_state": {"session_closed": True,
                                      "actions": len(sess["history"])},
        })
        del self.sessions[session_id]
        return True
