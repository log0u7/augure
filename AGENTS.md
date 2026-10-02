# AGENTS.md

## Project

augure: auditable exploitation decision layer (Ruby gem). Decides technique
selection from Datalog facts; never executes anything.

## Commands

- Test: `bundle exec rspec` (all green required, 79+ examples)
- Lint: `bundle exec standardrb` (zero offenses required, `--fix` available)
- Audit: `bundle exec bundler-audit`
- CLI: `bundle exec ruby exe/augure analyze spec/fixtures/... --json`

## Non-negotiable rules

1. **TDD**: failing test first. Bug fix = regression test first. No prod
   code without a test demanding it.
2. **Zero runtime dependencies** in the gemspec. Externals (solvers, LLM,
   Souffle) only via subprocess/HTTP boundaries.
3. **Rules are data**: technique logic goes in `lib/augure/rules.rb` table,
   never in ad-hoc code. The corpus conformance spec
   (`spec/fixtures/ctf_corpus.json`) is the contract: a rules change that
   moves a corpus verdict must update the corpus in the same commit and
   justify it.
4. **Conventional Commits**, atomic, English: `feat(engine): ...`,
   `fix(facts): ...`. One commit = one change + its test. CHANGELOG.md
   `[Unreleased]` updated in the same commit for feat/fix.
5. **No exploit code, no payloads** - technique metadata only.
6. **Claims discipline**: corpus numbers are predictions, not field results.
   Do not upgrade wording.
7. **Fail loudly**: parser errors carry line numbers; solver unknowns are
   `:unknown`, never silent nils.

## Style

- Ruby 3.4+, standard (not rubocop), frozen_string_literal in every file.
- snake_case methods, predicate methods end in `?`, Structs without
  keyword_init (standard preference).
- Docs in `docs/` follow Diataxis: tutorial / how-to / reference /
  explanation, one type per file.

## Gotchas

- Ruby runs via mise: `export PATH="$HOME/.local/share/mise/shims:$PATH"`
  in fresh shells, or prefix `mise exec --`.
- `stub` is an RSpec method: never name a spec local variable `stub`.
- Spec fixture paths: `spec/augure/*.rb` is two levels deep from repo root -
  fixtures live at `__dir__/../fixtures/`, exe at `__dir__/../../exe/`.
