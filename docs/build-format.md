# The build format: from a decision to bytes

augure decides; the pack says how the decision becomes a payload.
This page documents the BUILD format: the slots vocabulary, how a
technique becomes buildable, and where every number comes from.

## The lineage (all published)

The build layer descends from a line of published work:

- **metasm** - Y. Guillot, *"Metasm: un framework de manipulation de
  code en Ruby"*, SSTIC 2007 (also hack.lu 2007).
- **Déprotection semi-automatique de binaire** - Guillot & Gazet,
  SSTIC 2008: static unpacking driven by metasm's disassembler.
- **Exploitation automatique avec metasm** - esec-lab (Sogeti),
  June 2010: the automatic-exploitation loop this project re-derives,
  auditable this time.
- **miasm** - C. Desclaux, SSTIC 2012: metasm's Python successor. The
  strategy-sim prototype carries a miasm backend in its profiler - the
  docstring says "Python equivalent of Metasm", literally.
- **Ghost writing** - screwnomore, 2015: shellcode as preprocessor
  templates that mutate per build. Our shellcode stubs are assembly
  SOURCE with equivalent variants picked by a seeded rng.

## Where the numbers come from

| Number | Source | Provenance in the trail |
|---|---|---|
| the offset | the frame read statically (`lea reg, [rbp-N]` before the unsafe call) or the cyclic pattern crashed under the debugger | `offset_source: static-frame` / `gdb-cyclic` |
| the return address | the facts: `win_symbol("win", addr)` or a gadget address | `ret_source: win_symbol:win@0x...` |
| the gadget | the profiler's byte patterns, then RE-DECODED at the claimed address (a lying gadget is refused) | the gadget fact's address |
| the shellcode | assembly SOURCE in `augure-profiler/shellcode.rb`, assembled by metasm | the stub name |

Nothing is guessed. A number the facts cannot supply is a loud
`BuildError`, never a magic constant.

## The slots vocabulary

A build layout is an ordered list of slots (data, in
`lictor/lib/config/build_layouts.yml` or a pack's `build:` section):

| Slot | Arguments | Emits |
|---|---|---|
| `padding` | `measured_offset`, optional `sled` | the measured offset of `A` (or `\x90`) |
| `qword` | `win` or `gadget:TYPE` | the fact's address, 8 bytes |
| `dword` | same | 4 bytes (x86) |
| `shellcode` | `sh` or `bash` (or `file` with `--payload-file`) | the assembled stub |

The armor validates a pack's `build:` section: the technique must be
the pack's own, the layout must be a slot list, the refs must name
existing predicates. A refused layout never reaches the builder.

## What metasm does here

1. **The frame read** (`StaticOffset`): decode the ELF, resolve the
   unsafe imports' PLT stubs (`.rela.plt` order; both the classic
   `.plt` and the CFI `.plt.sec` layouts), disassemble `.text` from
   every function symbol, net the `e8 rel32` call to an unsafe sink,
   read the buffer's `rbp` displacement: offset = saved rbp + return
   slot - displacement. Validated against the canonical numbers
   (ROP Emporium ret2win x64 = 40, split = 40).
2. **The shellcode**: `Metasm::Shellcode.assemble` on committed
   assembly text; the call-back layout keeps every stub
   position-independent; the live-execution test in the suite runs our
   own assembled bytes.
3. **The gadget verification**: the bytes at a claimed gadget address
   are re-decoded and must match the advertised semantics.
4. **The crash identification**: the static side names the vulnerable
   function and its sink; the control evidence is the known pattern
   found in the registers - exact, not inferred from 0x41414141 shapes.
5. **The general gadget hunt**: every offset of the executable
   sections, a decoded chain ending on ret, classified semantically -
   the multi-instruction gadgets (pop rsi; pop r15; ret) the byte
   patterns never see.
6. **The dynamic layer**: the write-site proof (a watchpoint on the
   return slot catches the instruction that plants the overflow - the
   taint proven, not inferred), the runtime map (libc, stack of a live
   run), and lictor's harvest (the service's banner becomes
   leaked_address facts).
7. **The encoders**: the keyed self-decoder with the backward-call
   get-pc (a negative rel32 carries ff bytes, never 00), the payload
   nop-padded under 128 bytes, the keys per seed. The shikata
   inheritance, auditable: the seed reproduces the exact bytes. A
   payload wider than 120 bytes on a 0x00 channel is refused honestly.

No emulation: the suite's live-execution tests are the truth.

## Teaching a buildable technique

Write the pack (rules, kb, mcts, priors per the pack format), add its
`build:` section with the layout, run the armor:

```sh
lictor rule validate my_pack.yml   # the armor + the corpus guard
lictor rule install my_pack.yml    # the technique becomes decidable AND buildable
lictor plan target.facts --packs packs/
lictor build ret2mything --facts target.facts -a targets.yml
```

The LLM path goes through the same armor: `validate_pack` and
`scaffold_exploit` on the MCP surface are the same doors, staged for
review.
