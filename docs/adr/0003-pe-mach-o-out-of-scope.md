# ADR 0003: PE/Windows (and Mach-O) are out of scope for v0.x

## Status

Accepted (2026-10-04). A documented renouncement, not an oversight.

## Context

Professional red teams live substantially on Windows, and PE support
would open that market. But the entire read path is ELF-specific:
metasm ELF decoding, GNU_STACK/GNU_RELRO parsing, .plt/.plt.sec
layouts, GOT mechanics in the layouts, the triage backends (gdb),
checksec facts keyed to ELF structures. The fact schema itself
(nx/pie/canary/relro...) is mostly reusable; the profiler is not.

## Decision

PE (and Mach-O) are out of scope for v0.x. No shim, no half-port, no
"experimental" PE path that mislabels facts. When the abstraction debt
from ADR 0001 is paid and the core loop (decide -> build -> run ->
learn) is closed, a PE profiler is the natural second front - as a
parallel Profiler class emitting the same fact vocabulary, with
Windows-specific facts added to the schema deliberately.

## Consequences

- We renounce the Windows red-team market explicitly for now; the
  positioning says binary exploitation on ELF/Linux, honestly.
- The fact schema is designed to stay format-neutral so the future PE
  emitter is additive, not a rewrite.
- Nothing in the current rules or packs is expected to transfer
  unvalidated: Windows techniques (FSOP, cfg bypass...) would enter as
  packs with their own provenance, like every other technique.
