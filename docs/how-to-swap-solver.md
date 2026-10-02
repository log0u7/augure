# How to: plug a real SMT solver

Assumes augure is installed. Goal: route the numerical checks through z3,
bitwuzla or cvc5 instead of the arithmetic fast path.

## 1. Install a solver

```sh
apt install z3          # or brew install z3
# bitwuzla and cvc5 have upstream binaries
```

## 2. Emit the SMT-LIB and solve it

```ruby
require "augure"

smt = Augure::Verifier.payload_fits_smtlib(256, 40)
puts smt
# (set-logic QF_LIA)
# (declare-const buffer_size Int)
# (assert (= buffer_size 256))
# (assert (>= buffer_size 40))
# (check-sat)

status = Augure::SmtProcess.solve(smt, solver: "z3")
# => :sat
```

The contract is text-in, status-atom-out:

| Return | Meaning |
|---|---|
| `:sat` | constraint satisfied |
| `:unsat` | constraint violated |
| `:unknown` | solver missing, timed out, or answered garbage |

`:unknown` is deliberate: a verification *failure* must be visible and
logged, never a crash. Treat `:unknown` as "do not claim verified".

## 3. Solver options

```ruby
Augure::SmtProcess.solve(smt, solver: "bitwuzla", timeout: 5)
```

- `solver` - any binary that reads SMT-LIB v2 on stdin.
- `timeout` - seconds (default 10). Expiry returns `:unknown` and kills the
  child process.

## 4. Which path should you use?

The arithmetic fast path answers the same questions without a subprocess:

| | arithmetic | SMT solver |
|---|---|---|
| latency | nanoseconds | milliseconds (process spawn) |
| dependencies | none | solver binary |
| audit value | provable by inspection | provable by solver certificate |

Default to arithmetic; reach for the solver when a check outgrows integer
arithmetic (bit-vectors, arrays, string constraints). The corpus spec pins
both paths to the same answers, so switching never silently changes a
verdict.

## Troubleshooting

- **`:unknown` with a solver installed** - run the emitted text manually:
  `augure ... ` no; simply `z3 < smt.txt` and read its stdout. Augure only
  parses a bare `sat`/`unsat` token; solver banners are fine, they are
  ignored.
- **Permission denied** - the solver path is not executable; give the
  absolute path.
