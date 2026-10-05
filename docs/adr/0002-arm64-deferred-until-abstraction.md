# ADR 0002: ARM64 support is deferred, gated on the arch abstraction

## Status

Accepted (2026-10-04). Planned after ADR 0001's abstraction lands.

## Context

The modern CTF world is increasingly ARM64 (Raspberry Pi, phones,
boards), and the tool is x86/x64-only. The decision layer (rules,
packs, engine, bandit, MCTS) is architecture-neutral already; the cost
is entirely in the profiler. Porting today, with the arch branch pasted
six times (ADR 0001), is the expensive order of work.

## Decision

ARM64 comes AFTER the `AugureProfiler::Arch` abstraction. The port
itself is then: arm64 gadget patterns, AArch64 cpu in GadgetHunt and
StaticOffset, arm64 shellcode sources and equivalence pools, encoder
register names. The pack DSL needs no change (a pack already says
`match gadget csu` - the naming vocabulary carries the arch).

## Consequences

- We accept being x86/x64-only for now; that is where the current
  corpus (33 frozen targets), the lab and the parity harness live.
- The deferred port is cheap by construction: data plus one Arch, no
  surgery. Anything profiling-shaped learned meanwhile (new gadget
  classes, PE work) should be written arch-aware from the start.
- QEMU user-mode targets can exercise arm64 profiling in CI when the
  port lands.
