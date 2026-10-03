# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Static parity on the real binaries: a CI job downloads the eight
  sha256-pinned ROP Emporium x64 binaries, profiles binary + shipped
  libraries, and asserts every statically-derivable corpus claim
  (96 checked; write-up-only facts are reported as skipped, never
  silently dropped). The profiler learned the mov [r14], r15 encoding,
  and the corpus lost two copy-paste defects (a duplicated format1
  entry, badchars claiming write4's mov-deref-write gadget).

### Fixed

- The sub-gemspecs (augure-profiler, augure-mcp) declare relative
  `bindir`/`require_paths` again: absolute values break RubyGems
  `full_require_paths` (the require path gets joined against the gem
  dir), so the gems were unrequirable in CI and in the `augure-profile`
  subprocess. The `files` globs stay anchored to `__dir__` so a gem
  builds identically from any working directory.

### Added

- Technique packs: complete techniques as YAML data (rules, KB, MCTS
  transitions, priors, mandatory provenance), validated by the armor
  (constrained vocabulary, existing predicates only, stratification,
  new heads only) and the corpus guard (a pack may not reorder an
  existing technique or take a documented target's top-1).
- The network fact vocabulary: service/software_version/remote emitted
  from nmap scans; `verified("remote")` = the differential confidence
  level (modeled-from-ELF vs remote-verified).
- The profiler detects win/flag symbols (the target_function fact).
- The shipped corpus (lib/augure/ctf_corpus.json) enables the corpus
  guard at consumer runtime.
- augure-mcp: the read-only MCP surface (analyze_target, list_rules,
  explain_technique).

## [0.1.0] - 2026-10-02

### Added

- Project scaffold: gemspec, RSpec, Standard linting, CI skeleton.
- Core decision layer: Facts (strict parser), Rules-as-data + Engine with
  provenance, Bandit (seeded Thompson sampling), MCTS planner, KnowledgeBase
  (TF-IDF + prior calibration), Verifier with SMT-LIB subprocess boundary,
  Pipeline facade and `augure analyze` CLI.
- CTF benchmark corpus: 34 targets across ROP Emporium, Protostar, Phoenix
  and pwnable-style suites; 5 MCTS planning scenarios; byte-identical parity
  with the frozen Python engine (24/24 classification, 5/5 plans).
- Extended technique vocabulary, all documented by public suites:
  fmtstr_leak, ret2dlresolve, ret2csu, stack_pivot, got_overwrite.
- `augure-benchmark`: per-suite concordance harness with exit-code gate;
  dedicated CI job.
- `augure-profiler` gem (metasm isolated, LGPL): ELF in, facts out -
  checksec, PLT imports, unsafe-symbol hints, semantic gadget
  classification; `augure-profile` CLI; compiled-binary test suite.
- Documentation: commercial README (mermaid pipeline), Diataxis suite
  (tutorial, how-tos, reference, architecture), auditability page with
  red/blue/purple team sections.

