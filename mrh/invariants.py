"""The invariant registry and the evaluability classes — Part I §2.6, Part III §9.1.

An invariant in CROA is not a sentence in a policy document. It is a registry entry
carrying a declared evaluability class, a declared trajectory profile, and — where it is
decided by an approximated method — a pinned analyzer identity and a budget. Those
declarations are what make `C2.eval` deterministic (I2) and what make a decision
reconstructable years later (I3).

The class that matters here is `E3`. Part I §2.6:

    "An E2 or E3 evaluation that cannot return SATISFIED or VIOLATED MUST return
    AMBIGUOUS, and an AMBIGUOUS verdict MUST be treated as a deny (fail-deny)."

The analyzer is therefore allowed to not know. What it is not allowed to do is guess,
or exceed its budget silently, or return a verdict that a later run would not reproduce.
`event.analyzer_version` is recorded on every decision an E3 method took part in,
because two decisions on identical inputs that differ because the analyzer changed are
otherwise indistinguishable from a determinism failure.
"""

SATISFIED = "SATISFIED"
VIOLATED = "VIOLATED"
AMBIGUOUS = "AMBIGUOUS"

EVALUABILITY = ("E1", "E2", "E3")
TRAJECTORY_PROFILES = ("TP-0", "TP-W", "TP-C", "TP-X")


class Invariant(object):
    """One registry entry (Part III §9.1).

    Every field below is mandatory in the specification's registry table; the Validation
    step of the GitOps pipeline (§7.2, Step 3) fails a change request that omits one.
    """

    def __init__(self, identifier, statement, evaluability="E1", enforcement="BLOCKING",
                 reversibility="R2", trajectory_profile="TP-0", predicate=None,
                 analyzer=None, aggregate=None):
        if evaluability not in EVALUABILITY:
            raise ValueError("%r is not an evaluability class" % evaluability)
        if trajectory_profile not in TRAJECTORY_PROFILES:
            raise ValueError("%r is not a trajectory rule profile (§4.6.3)" % trajectory_profile)
        if evaluability == "E3" and analyzer is None:
            # §9.1: an E3 entry MUST declare a pinned analyzer identity, a budget, and a
            # governance-friction target. An E3 invariant without an analyzer has no
            # evaluation method at all, so it cannot be registered.
            raise ValueError("%s is E3 and declares no pinned analyzer" % identifier)
        if trajectory_profile in ("TP-C", "TP-X") and aggregate is None:
            # §4.6.3: a cumulative invariant MUST declare its aggregation function,
            # threshold and window.
            raise ValueError("%s is %s and declares no aggregate" % (identifier, trajectory_profile))

        self.id = identifier
        self.statement = statement
        self.evaluability = evaluability
        self.enforcement = enforcement
        self.reversibility = reversibility
        self.trajectory_profile = trajectory_profile
        self.predicate = predicate            # E1/E2: a total function over the action
        self.analyzer = analyzer              # E3: a pinned analyzer
        self.aggregate = aggregate            # TP-C/TP-X: {"function", "field", "alert_threshold", "hard_limit", "window"}

    def evaluate(self, action):
        """Returns (verdict, analyzer_version_or_None).

        E1 and E2 are decided by a total predicate and never return AMBIGUOUS. E3 is
        decided by the pinned analyzer, which may.
        """
        if self.evaluability == "E3":
            return self.analyzer.analyze(self.id, action), self.analyzer.version
        if self.predicate is None:
            return SATISFIED, None
        return (VIOLATED if self.predicate(action) else SATISFIED), None

    def __repr__(self):
        return "<Invariant %s %s %s>" % (self.id, self.evaluability, self.trajectory_profile)


class E3Analyzer(object):
    """A pinned semantic analyzer (Part I §2.6, Part III §9.1, §11.5).

    Approximated by construction: Rice's theorem denies an exact, total, deterministic
    procedure for the general case, so the honest interface has three outcomes and not
    two. `budget` is the declared bound beyond which the analyzer MUST return AMBIGUOUS
    rather than keep working — an analyzer without a declared budget cannot return a
    reproducible verdict, because the answer would depend on how long it happened to run.

    `stub` installs a fixed verdict for a payload, which is precisely what NT-005's setup
    calls for: "the E3 analyzer is configured (or a test stub is installed in the
    conformance test harness) to return AMBIGUOUS for the specific SQL payload defined in
    the input below."
    """

    def __init__(self, version, budget_ms=250, decide=None):
        self.version = version                # pinned: §11.5 forbids upgrading in place
        self.budget_ms = budget_ms
        self._decide = decide
        self._stubs = {}
        self.calls = []

    def stub(self, payload_key, verdict):
        """Install a fixed verdict for one payload (NT-005 setup)."""
        if verdict not in (SATISFIED, VIOLATED, AMBIGUOUS):
            raise ValueError("%r is not an analyzer verdict" % verdict)
        self._stubs[payload_key] = verdict
        return self

    def analyze(self, invariant_id, action):
        key = action.get("payload_key") or action.get("target")
        if key in self._stubs:
            verdict = self._stubs[key]
        elif self._decide is not None:
            verdict = self._decide(invariant_id, action)
        else:
            # No method configured for this payload. Not knowing is a verdict.
            verdict = AMBIGUOUS
        self.calls.append((invariant_id, key, verdict))
        return verdict


class InvariantRegistry(object):
    """The registered set, versioned (Part III §9.1, §11.3)."""

    def __init__(self, invariants=(), version="inv-2026-09-01"):
        self.version = version
        self._by_id = {}
        for inv in invariants:
            self.register(inv)

    def register(self, invariant):
        self._by_id[invariant.id] = invariant
        return invariant

    def __iter__(self):
        return iter(self._by_id.values())

    def __getitem__(self, identifier):
        return self._by_id[identifier]

    def applicable(self, action):
        """Every registered invariant is in scope for every action in this demonstrator.

        A deployment scopes invariants by action class and target; doing so here would
        hide the thing the harness is for, which is showing that an invariant is
        evaluated rather than assumed.
        """
        return list(self._by_id.values())

    def trajectory_relevant(self):
        return [i for i in self._by_id.values() if i.trajectory_profile != "TP-0"]
