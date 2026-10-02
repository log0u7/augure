# Architecture: why rules-as-data survives migrations

*Explanation. The design rationale, and the twenty years behind it.*

## The one decision that outlived everything

The lineage behind augure spans four languages: Perl (2007-2012, SWI-Prolog
reasoner + genetic algorithm), a brief Ruby interlude, a Python
neuro-symbolic prototype (2024-2026), and now Ruby again. Technologies did
not survive those migrations - one design decision did:

> **Separate what the target IS (facts) from what you DO about it (rules),
> and make both data.**

Everything else was replaced. The fact schema changed shape; the rules
changed vocabulary; the reasoner went Prolog, then a compiled Datalog
engine, then hand-rolled forward chaining. The *separation* is what made
each migration a port instead of a rewrite: facts in, rules in, new engine
out, corpus verdicts must not move.

## Why a rule table and not code

The obvious Ruby implementation of "applicable techniques" is a case
statement. It would be shorter. It would also fail three ways:

1. **No provenance.** A case statement answers "what"; only data can answer
   "which rule fired because of which facts". The explain payload is free
   when rules are rows.
2. **No second engine.** Rules-as-data can be *generated into* a Souffle
   .dl program, so a compiled Datalog engine and the Ruby engine can be
   conformance-tested against each other. Code cannot be conformance-tested
   against itself. The Python prototype died exactly here: its Souffle rules
   and its Python fallback drifted apart silently; augure makes that class
   of drift a CI failure.
3. **No reverse reading.** A blue team asks "which protections kill which
   techniques?" - answerable by table traversal, not by tracing code.

## The engine is boring on purpose

Forward-chaining fixpoint over a tiny rule set: derive tuples until nothing
new derives. No backtracking, no unification beyond equality, no cuts. The
entire semantics fits in one file and one afternoon of reading. Boring is
the point: auditable systems are systems a reviewer can finish.

Negation is stratified by convention (only on input facts) and enforced by
the corpus spec. Defaults are closed-world (`nx` absent means `nx("true")`)
- documented, tested, and the single most surprising line in the engine.

## Uncertainty, in three layers

1. **Genetic algorithm (offline).** Evolved weight vectors over synthetic
   targets; found the inversions humans miss. Research tool, stays in
   Python - it is the narrative, not the SDK.
2. **Bandit (online, flat).** Thompson sampling over Beta posteriors.
   Adapts per target, remains auditable (seeded draws, logged feedback).
   Blind spot: treats choices as independent.
3. **MCTS (sequential).** Plans multi-step trajectories: a leak is worth
   what it unlocks, which no flat weight can express. The STAGE_MODEL is a
   transition table - data again, so the planner stays inspectable.

The progression mirrors the published articles: the engine is the decision
layer, the planner is article 3, and the corpus is what keeps all of it
honest.

## Subprocesses are the API policy

Soufflé, SMT solvers, LLM providers: every external capability enters
through a serialization boundary (facts text, SMT-LIB text, HTTP). That is
what makes the zero-runtime-dependency gem possible, keeps native-extension
attack surface at zero, and lets a consumer swap bitwuzla for cvc5 or an
LLM backend without touching the core. The articles called it "interfaces
are serialization boundaries"; the implementation is the proof.

## What comes next, and why it does not change this

Phase 2 adds a metasm profiler (binary in, facts out) and Phase 3 adds LLM
feature extraction - both emit *facts* into the same boundary. The LLM
hypothesis generator from the articles stays behind the whitelist: it
proposes facts, the schema rejects anything else, the engine never sees a
prose sentence. The architecture survives new proposal sources because the
contract was never "trust the source"; it is "speak fact, or leave".
