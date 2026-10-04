# Reference: fact format, rules table, API

Version: augure 0.1.x.

## Fact format

One fact per line: `predicate("string-atom").` or `predicate("atom", 42).`
Blank lines and `// comments` ignored. Rules (`:-`) rejected. Unknown
predicate, wrong arity or wrong argument type raises an explicit error with
the line number.

### A complete example

This is the shape of a `target.facts` file (see the
[tutorial](tutorial.md) for the full walkthrough):

```
// the target
nx("true").
pie("false").
canary("false").
relro("partial").

// what it imports
plt("system").
plt("puts").

// what gadgets exist inside it
gadget("pop_rdi_ret", 4198400).
gadget("ret_align", 4198404).

// what the profiler noticed
vuln_hint("unsafe_func:gets").
```

### Schema

| Predicate | Arity | Arg types | Meaning |
|---|---|---|---|
| `nx` | 1 | string | data execution prevention (`"true"`/`"false"`) |
| `win_symbol` | 2 | string, integer | the winning function's name and address (emitted by the profiler) |
| `crash_site` | 1 | string | the crash's identification: `ret` when the control is confirmed by the planted pattern |
| `vuln_function` | 1 | string | the vulnerable function the static frame read named |
| `sink` | 1 | string | the unsafe sink (strcpy, gets, ...) the static read identified |
| `pie` | 1 | string | position-independent executable |
| `canary` | 1 | string | stack canary present |
| `relro` | 1 | string | `"none"`, `"partial"`, `"full"` |
| `plt` | 1 | string | imported function name |
| `gadget` | 2 | string, integer | gadget semantic type + address |
| `vuln_hint` | 1 | string | profiler hint, e.g. `"unsafe_func:gets"` |
| `vuln` | 1 | string | explicit vuln class: `sof`, `fmtstr`, `heap` |
| `target_function` | 1 | string | win-style function present |
| `libc_present` | 1 | string | libc known/version pinned |
| `allocator` | 1 | string | `tcache`, `ptmalloc2`, `dlmalloc` |
| `glibc_minor` | 1 | integer | glibc minor version |
| `return_addr_filtered` | 1 | string | return addresses constrained (stack6-style) |
| `got_overwrite_target` | 1 | string | GOT overwrite viable |
| `function_pointer_on_heap` | 1 | string | heap function pointer |
| `seccomp` | 1 | string | seccomp filter context |
| `shellcode_input` | 1 | string | input reachable and executable |
| `sigreturn_frame` | 1 | string | sigreturn frame constructible |
| `fmtstr_read` | 1 | string | format string has a read primitive |
| `reloc_writable` | 1 | string | relocations writable (ret2dlresolve) |
| `dt_lazy` | 1 | string | lazy binding in effect |
| `limited_stack` | 1 | string | stack space constrains the chain |
| `service` | 1 | string | remote service name (nmap: `ssh`, `http`...) |
| `software_version` | 1 | string | remote product + version (from the scan) |
| `remote` | 1 | string | the facts describe a remote service, not a local ELF |
| `verified` | 1 | string | `"remote"` = validated by a differential probe: the remote faults like the local model |

Defaults (closed world): absent `nx` = `"true"`, absent `pie` = `"true"`,
absent `canary` = `"false"`.

## Rules table (applicability)

| Rule ID | Head | Fires when |
|---|---|---|
| `app_shellcode` | `shellcode` | sof, NX off, no canary, return not filtered |
| `app_ret2func` | `ret2func` | sof, PIE off, target function present |
| `app_ret2plt` | `ret2plt` | sof, NX on, PIE off, `system` imported |
| `app_ret2libc_plt` | `ret2libc` | sof, `__libc_start_main` imported |
| `app_ret2libc_libc` | `ret2libc` | sof, libc present |
| `app_rop` | `rop` | sof, NX on, gadget supply (pop or mov-store) |
| `app_srop` | `srop` | sof, sigreturn frame, syscall gadget |
| `app_ret2plt_leak` | `ret2plt_leak` | sof, NX on, PIE on, `puts`, reg control |
| `app_fmtstr_write` | `fmtstr_write` | format-string vuln (NX-independent) |
| `app_fmtstr_leak_read` | `fmtstr_leak` | fmtstr + read primitive |
| `app_fmtstr_leak_pie` | `fmtstr_leak` | fmtstr + PIE on |
| `app_fmtstr_leak_canary` | `fmtstr_leak` | fmtstr + canary on |
| `app_ret2dlresolve` | `ret2dlresolve` | sof, NX on, PIE off, lazy binding, writable reloc |
| `app_ret2csu` | `ret2csu` | sof, NX on, csu gadget family |
| `app_stack_pivot` | `stack_pivot` | sof, NX on, limited stack, pivot gadget |
| `app_got_overwrite_sof` | `got_overwrite` | sof, NX on, GOT target, not full RELRO |
| `app_got_overwrite_fmtstr` | `got_overwrite` | fmtstr, GOT target, not full RELRO |
| `app_heap_tcache_alloc` | `heap_tcache` | heap, allocator tcache |
| `app_heap_tcache_glibc` | `heap_tcache` | heap, glibc 2.26..2.33 |
| `app_heap_fastbin_glibc` | `heap_fastbin` | heap, glibc < 2.26 |
| `app_heap_fastbin_alloc` | `heap_fastbin` | heap, allocator ptmalloc2 |
| `app_heap_overwrite_dlmalloc` | `heap_overwrite` | heap, dlmalloc |
| `app_heap_overwrite_fp` | `heap_overwrite` | heap, function pointer on heap |

Derived relations: `vuln` (from hints), `has_reg_control`,
`has_write_primitive`, `has_syscall_gadget`, `has_csu_gadget`,
`has_pivot_gadget`, `enough_gadgets`.

## CLI

```
augure analyze <facts-file | -> [--json] [--seed N] [--packs DIR]
```

| Flag | Effect |
|---|---|
| `--json`, `-j` | machine-readable decision |
| `--seed N`, `-s N` | deterministic bandit/MCTS draws |
| (stdin) | `-` reads facts from stdin |

Exit codes: `0` decision emitted, non-zero on malformed facts (message on
stderr names the line).

## Ruby API

### `Augure::Facts`
- `.parse(text) -> Facts` - strict parse, raises `MalformedFact` /
  `UnknownPredicate` with line numbers.
- `.from_file(path) -> Facts`
- `#rel(name) -> Array<[arg, ...]> | nil` - tuples by relation.
- `#merge(other) -> Facts` - combined copy.
- `#to_s -> String` - deterministic emission; round-trips.

### `Augure::Engine`
- `.new(facts, rules: Rules.all)`
- `#run -> Result`
- `Result#applicable -> [String]` - rule-table order.
- `Result#derived(rel) -> [tuple]`
- `Result#provenance(technique) -> [{rule:, evidence:}]`

### `Augure::Bandit`
- `.new(priors: {"tech" => [alpha, beta]}, rng: Random.new)`
- `#arm(tech) -> Arm` (auto-arms unknown with (1, 1))
- `#select(verified) -> String | nil` - Thompson sample argmax.
- `#feedback(tech, success)` - updates posterior, logs history.
- `#rankings -> [String]` - prior-mean order, deterministic.

### `Augure::Mcts`
- `.plan(allowed, iterations: 2000, seed:) -> [first_move, path]`
  (`model:` overrides the transition graph; technique packs merge into
  it via `merged_model(packs)`)
- `.available(caps, allowed)`, `.transition(caps, tech)`, `.terminal?(caps)`
- `STAGE_MODEL` - the technique transition graph.

### `Augure::Pack` / `PackLoader`
- `Pack.load_file(path)` - validates a technique pack (YAML): schema,
  existing predicates only, stratification, new heads only, mandatory
  provenance (author + source).
- `PackLoader.load_dir(dir) -> [Pack]`,
  `.corpus_guard(packs)` - refuses any pack that reorders an existing
  technique or takes a documented target's top-1.
- Packs are data the consumer owns; the canonical example lives at
  `packs/ret2csu_v2.yml` in the augure repo.

### `Augure::Verifier`
- `.payload_fits(buffer_size:, payload_min:) -> :sat | :unsat`
- `.bad_bytes?(payload:, bad_bytes:) -> bool`
- `.rop_chain_feasible?(...) -> bool`
- `.payload_fits_smtlib(buffer_size, payload_min) -> String`

### `Augure::SmtProcess`
- `.solve(smt_text, solver:, timeout: 10) -> :sat | :unsat | :unknown`

### `Augure::Pipeline`
- `.analyze(facts:, seed: nil, priors: nil, buffer_size: 256,
  packs: nil, plan: true) -> {applicable:, verified:, ranking:, selected:,
  plan:, explain:}` - `packs:` merges technique packs (rules, priors,
  MCTS transitions); `plan: false` skips the MCTS search (the corpus
  guard uses it).

### Machine payload contract

`augure analyze --json` emits the decision hash stamped with a stable
schema tag:

```json
{ "schema": "augure/decision@1", "applicable": [...], ... }
```

Consumers (CI, agents, the MCP server) pin `augure/decision@1`; a
breaking change bumps the tag and is documented in the CHANGELOG.

### Taught technique packs

The shipped packs extend the rule table as data (`packs/`, loaded with
`augure analyze --packs DIR` or taught to lictor with
`lictor rule install`): `house_force`, `house_orange`, `house_botcake`,
`unsorted_bin_attack`, `fastbin_hook`, `ret2dlresolve_x86`,
`got_partial_overwrite`, `brop` (the first rule that consumes
`verified("remote")` - an observation anchors it), `ret2partial_overwrite`,
`one_gadget` - plus the canonical `ret2csu_v2` example. Each carries its
rules, knowledge-base entries, MCTS transition and Beta priors, with the
author and source as provenance. Pack priors fill the gaps of the prior
table; a consumer-provided or outcome-adapted entry always wins.

### `Augure::KnowledgeBase`
- `.corpus -> [entry]` (22 documented patterns)
- `.corpus_with(extra) -> [entry]` (seed corpus + technique-pack knowledge)
- `.priors -> {"tech" => [alpha, beta]}` (N=10 pseudo-counts)
- `.transitions -> {"tech" => [unlock, ...]}`
- `#query(text, technique: nil, n_results: 3) -> [{doc:, score:}]`

## MCTS stage model

| Technique | Requires | Provides | Terminal | Base success |
|---|---|---|---|---|
| `fmtstr_leak` | - | libc_base | no | 0.75 |
| `fmtstr_canary` | - | canary | no | 0.70 |
| `ret2plt_leak` | - | libc_base | no | 0.68 |
| `ret2libc` | libc_base | shell | yes | 0.85 |
| `rop` | libc_base | shell | yes | 0.75 |
| `rop_nocontext` | - | shell | yes | 0.25 |
| `ret2plt` | - | shell | yes | 0.75 |
| `shellcode` | - | shell | yes | 0.90 |
| `stack_pivot` | - | pivot | no | 0.60 |
| `ret2plt_leak_big` | pivot | libc_base | no | 0.68 |
| `ret2libc_big` | pivot+libc_base | shell | yes | 0.85 |
| `ret2csu` | - | libc_base | no | 0.70 |
| `dlresolve` | - | shell | yes | 0.55 |
| `got_overwrite` | - | shell | yes | 0.65 |
| `io_uring_register` | - | iouring | no | 0.90 |
| `rds_pin_steal` | iouring | pin_underflow | no | 0.70 |
| `page_free` | pin_underflow | freed_page | no | 0.75 |
| `pagecache_reclaim` | freed_page | pagecache_ctrl | no | 0.65 |
| `io_uring_write` | pagecache_ctrl+iouring | suid_overwrite | no | 0.70 |
| `suid_exec` | suid_overwrite | shell | yes | 0.90 |

The last six are the PinTheft chain (V12 Security), an externally documented
ordering - augure only tests whether the planner reproduces it.
