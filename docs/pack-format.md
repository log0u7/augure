# Pack format: teach augure a new technique (as data)

*How-to. For operators and LLM agents. You write a YAML file; the armor
decides whether augure learns it.*

## The one rule before anything

**You write data, never code.** A pack is a constrained YAML document.
If your intent needs something the format cannot express, the format
will refuse it - that is the design, not a bug. The vocabulary exists
so that a wrong pack is impossible, not merely discouraged.

## Anatomy

```yaml
technique: my_new_technique      # [a-z0-9_]+ - the NEW technique's name
author: claude-code (session 2026-10-03)   # mandatory: who taught augure
source: https://...              # mandatory: a verifiable reference
rules:
  - id: app_my_new_technique     # convention: app_<technique>
    head: [applicable, my_new_technique]
    conditions:                  # ONLY the 4 forms below
      - [fact, vuln, sof]        # a tuple vuln("sof") exists
      - [not_fact, relro, full]  # absent (input facts ONLY)
      - [match, gadget, 0, pop]  # gadget arg 0 matches /pop/
      - [cmp, glibc_minor, ge, 26]  # integer arg >= 26
kb:
  - id: my_new_technique_001
    technique: my_new_technique
    description: >
      What the technique is, when it applies, what it needs. This is
      what the agent (or human) will read back from `augure explain`.
    chain: [step_one, step_two]
    unlocks: [libc_base]
    success_rate: 0.7             # 0..1 - authored, say so if uncertain
mcts:
  requires: []                   # capabilities needed before this runs
  provides: [libc_base]          # capabilities it unlocks
  terminal: false                # true only if it yields a shell
  success: 0.7                   # the planner's base success
priors: [14, 6]                  # Beta(alpha, beta): mean 0.7 here

# All three sections below are OPTIONAL:
build:                           # (check 8) the assembly order - packs
  technique: my_new_technique    # teach, lictor's builder follows
  layout:                        # slots: padding/qword/dword/shellcode/chain
    - [padding, measured_offset]
    - [chain, "gadget:pop_rdi_ret", "plt_addr:system"]

detection:                       # (check 9) the DEFENDER side - what the
  - channel: wire                # technique looks like to the defenses;
    signature: "cyclic padding then a non-mapped return"  # channel from
    note: "the padding phase"    # wire/syslog/syscall/crash/file

mitre:                           # (check 10) the ATT&CK mapping
  - T1068
```

## The checks (in the order the loader runs them)

1. **Condition vocabulary**: only `fact`, `not_fact`, `match`, `cmp`.
   Anything else - including "clever" ones - is refused.
2. **Existing predicates only**: your conditions may reference the 33
   input facts (see `docs/reference.md#schema` - the binary vocabulary:
   nx/pie/canary/plt/gadget/plt_addr/got_addr...; the network vocabulary,
   emitted from nmap scans: service/software_version/remote; the
   confidence marker: verified; the leaks: leaked_address) and the
   built-in derived relations (`vuln`, `has_reg_control`,
   `has_write_primitive`, `has_syscall_gadget`, `has_csu_gadget`,
   `has_pivot_gadget`, `enough_gadgets`). You cannot invent a fact
   source.
3. **Stratification**: `not_fact` on input facts only.
4. **New heads only**: your technique must be NEW. Overriding
   `ret2plt` or any built-in is refused - the corpus owns those verdicts.
5. **Priors and rates in range**: priors are exactly `[alpha, beta]`
   numbers; success rates in `[0, 1]`.
6. **Corpus guard**: with your pack loaded, all 33 frozen corpus
   targets must keep their documented ranking (your technique may rank
   BELOW the documented top). A pack that takes the top-1 of a
   documented target is refused - claiming better on frozen truth is a
   dev-time corpus update, not a runtime pack. Two documented
   exceptions: an entry with an EMPTY built-in verdict has nothing to
   move (additive packs extend it), and an entry documenting
   `pack_verdict: <technique>` polices the pack answer's ARRIVAL
   instead - the pwnable/orw case.
7. **match patterns and cmp operands fail at load**: a `match` pattern
   is precompiled (`RegexpError` at load, not at decision); `cmp`
   operands must be integers and operators from the engine's table -
   `"26"` or a typo'd operator never reaches the engine.
8. **build: (optional)**: must name its own technique; the layout must
   be a non-empty slot list from the vocabulary
   (padding/qword/dword/shellcode/chain). The builder interprets; the
   armor gates the vocabulary.
9. **detection: (optional)**: each entry needs a `channel` from
   wire/syslog/syscall/crash/file plus a concrete `signature` and
   `note` - a vague hint is not detection content.
10. **mitre: (optional)**: an array of ATT&CK technique codes
    (`T1068`, `T1068.001`) only.

## The optional `build:` and `detection:` sections

`build:` teaches the BUILDER the technique's assembly order (packs
teach, lictor's builder follows): the layout must be a slot list from
the vocabulary (padding/qword/dword/shellcode/chain - see
build-format.md), the technique must be the pack's own. Armor check 8.

`detection:` is the DEFENDER side of the technique - the corpus read
backwards. One entry per observable: `channel` from the constrained
vocabulary (wire/syslog/syscall/crash/file), a concrete `signature`,
and a `note` saying what the observable means. A vague hint is not
detection content - the armor rejects it (check 9). The blue team
consumes these with `augure rules --mitre` and the hardened-coverage
flow; a pack without `detection:` teaches the offense but leaves the
defense blind.

## The cycle

```sh
lictor rule validate my_pack.yml    # dry-run: schema + corpus guard
lictor rule install my_pack.yml     # interactive confirm, versioned, trailed
augure analyze target.facts         # your technique is now decidable
```

Via an MCP agent: the rules change every future decision - the
operator reads the validated pack before installing it.

## Writer's discipline (for agents especially)

- Copy `packs/ret2csu_v2.yml` (the canonical example) - change the
  substance, keep the structure.
- `success_rate` and `priors` are authored numbers: ground them in the
  source you cite, and say so in the description if they are estimates.
- If validation refuses you, read the refusal - each check names its
  reason. Fix the data; never look for a way around the armor.
- One pack = one technique. Split OR-conditions into sibling rules
  sharing the head; the provenance then carries EVERY reason that
  fired, each attributed to its own rule.
