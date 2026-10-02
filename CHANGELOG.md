# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
