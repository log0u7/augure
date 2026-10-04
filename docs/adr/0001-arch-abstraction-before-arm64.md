# ADR 0001: the arch abstraction before any port

## Status

Accepted (2026-10-04). Execution planned after the spine repairs; the
abstraction work happens opportunistically when the profiler files are
touched anyway.

## Context

The x64/x86 branch is pasted six times across the profiler gem
(profiler.rb:95, gadget_hunt.rb, static_offset.rb x2, shellcode.rb x2):
arch selection, gadget byte patterns, frame-read heuristics, shellcode
sources and encoder register names all assume x86/x64 inline. Adding a
third architecture today means touching every one of those sites and
hoping nothing was missed; the fact schema carries no arch field, so
gadget type names (jmp_rsp vs jmp_esp) are the only implicit carrier.

## Decision

Extract an `AugureProfiler::Arch` abstraction FIRST, before any port:
per-arch gadget byte patterns, word width, metasm cpu class, frame-read
heuristics, and shellcode source keys. The six call sites become one
lookup. Consumers (payload_builder, the encoders) read the abstraction,
never the branch.

## Consequences

- A new arch (ARM64) becomes data plus one new Arch definition, not
  surgery across six files - see ADR 0002.
- The refactor is behavior-preserving for x64/x86: the frozen corpus
  and the ROP Emporium parity job are the regression contract.
- The fact schema gains an arch dimension only when a second arch
  actually lands (YAGNI until then).