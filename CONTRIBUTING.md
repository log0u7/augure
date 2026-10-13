# Contributing to augure

Thanks for considering a contribution. This project values one thing above all:
**auditable correctness**. Every change must keep the decision layer
reproducible, explainable and honestly benchmarked.

## Setup

```sh
bin/setup                  # deps + toolchain check + first green run
bin/console                # IRB with the API pre-loaded (ret2win facts)
```

## Issues

- Open issues through the templates: **Bug report** or **Feature request**
  (search for duplicates first). Facts files and corpora excerpts are welcome
  in reproductions; full binaries are not.
- **Security problems never go to public issues.** Use GitHub private
  vulnerability reporting (see `SECURITY.md`).
- Inactive issues may be marked stale after 23 days and closed 7 days later
  without updates.

## Branching

- One branch per topic, cut from `main`:
  `feat/<scope>`, `fix/<scope>`, `chore/<scope>`, `docs/<scope>`, `test/<scope>`.
- `main` stays green at all times.
- Keep branch scope small: one topic, one review, one merge.

## Commits

**Conventional Commits, atomic.** One logical change per commit:

```
feat(engine): emit rule provenance in result
fix(facts): reject nested quotes in string atoms
test(corpus): add protostar stack6 anti-reflex case
docs(readme): clarify dry-run mode
chore(ci): add bundler-audit job
```

- Types: `feat`, `fix`, `test`, `docs`, `chore`, `refactor`, `perf`.
- Subject <= 50 chars, imperative mood, English. Body explains *why*.
- `feat:` commits ship their spec in the same commit; bug fixes ship a
  regression test that fails on `main` before the fix.
- `CHANGELOG.md` `[Unreleased]` is updated in the same commit for `feat`/`fix`.

## Pull requests

`main` is protected (repository ruleset): direct pushes are rejected.

1. Branch off `main`, implement with TDD (see below), keep the suite green.
2. Open the PR: Conventional Commit title, `Fixes #N` when an issue exists,
   complete the template checklist honestly.
3. CI must be green (rspec, standardrb, gem builds).
4. Merge with a merge commit, delete the branch.

Review expectations scale with contributors: while the maintainer is the
single author, own PRs are self-merged; with a second contributor, reviews
become required.

## The rules

1. **TDD, no exceptions.** Write the failing test first. A PR with no test
   is a rejected PR.
2. **Zero runtime dependencies.** The core gem ships with no runtime deps.
   External engines (SMT solvers, LLM providers) enter only through
   subprocess/HTTP boundaries.
3. **Rules are data**: technique logic goes in `lib/augure/rules.rb`, never
   in ad-hoc code. A rules change that moves a corpus verdict must update
   `lib/augure/ctf_corpus.json` in the same commit and justify it.
4. **No exploit code, ever.** The repo encodes technique *metadata* (rules,
   facts, checks), never payloads. See the acceptable-use section in README.
5. **Claims discipline.** Benchmarks are predictions against frozen corpora,
   not field results. Do not upgrade wording ("verified" means the corpus
   agrees, nothing more).
6. **SemVer.** Development is `0.y.z`: minor bumps may break. `1.0.0` waits
   for a stable public API.

## Lint and checks

```sh
bundle exec rspec          # all green required
bundle exec standardrb     # no offenses required
bundle exec bundler-audit  # before any release
```

## Releasing

1. Update `CHANGELOG.md`: move `[Unreleased]` to a dated section.
2. Bump `lib/augure/version.rb` (and the profiler/mcp server versions when
   they ship together).
3. `git commit -m "chore(release): v0.x.y"` through a pull request.
4. Tag `vX.Y.Z` on `main` AFTER the merge lands, on the exact merge commit,
   push tags one by one. The `release` workflow builds and pushes the gems.