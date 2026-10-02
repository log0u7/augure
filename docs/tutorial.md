# Get your first auditable decision in 10 minutes

*Tutorial. By the end you will have run Augure on a real fact file, read its
proof trail, and made it disagree with you on purpose.*

Prerequisites: Ruby 3.4+.

## 1. Install

```sh
gem install augure
augure --help
```

You should see the usage banner. **Check:** `Usage: augure analyze`.

## 2. Write a fact file

> **Where do facts come from?** From the profiler, not your keyboard:
> `augure-profile app.elf -o target.facts` generates exactly this file from
> a binary (checksec, imports, unsafe symbols, gadgets) via metasm - gem
> `augure-profiler`. Hand-writing facts is still useful to learn the
> format the profiler speaks.

Facts are one target's properties, one per line. Create `target.facts`:

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

**Check:** the file has no trailing `:-` and every line ends with `.`.

## 3. Decide

```sh
augure analyze target.facts
```

You should see:

```
applicable: ret2plt, rop
selected:   ret2plt
plan:       ret2plt
  ret2plt <- app_ret2plt (vuln=sof, nx=true, pie=false, plt=system)
  rop     <- app_rop (vuln=sof, nx=true, enough_gadgets=true)
```

Augure picked `ret2plt` - the technique human operators routinely skip in
favor of a ROP chain. The rules, not the reflex, made the call.

## 4. Read the proof

```sh
augure analyze target.facts --json | head -30
```

Find the `explain.provenance` block: the rule ID and the exact facts that
fired it. That block is the whole product: hand it to a colleague, they can
verify the decision without rerunning anything.

## 5. Reproduce it

```sh
augure analyze target.facts --json --seed 42 > run1.json
augure analyze target.facts --json --seed 42 > run2.json
diff run1.json run2.json && echo "identical"
```

Same input, same seed, same decision. **Check:** the diff is empty.

## 6. Make it disagree with you

Remove the `plt("system")` line and run again:

```sh
grep -v 'plt("system")' target.facts > no-system.facts
augure analyze no-system.facts
```

`ret2plt` vanished - and the proof trail explains why: the rule
`app_ret2plt` requires the fact you just removed. This is the loop the
whole tool is built on: change the facts, watch the decision move, know
exactly which rule moved it.

## Next steps

- [Write your own technique rules](how-to-write-rules.md)
- [The full reference](reference.md) - fact schema and API
- [What the proof trail buys each team](auditability.md)
