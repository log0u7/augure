# Contributing to augure

Thanks for considering a contribution. This project values one thing above all:
**auditable correctness**. Every change must keep the decision layer
reproducible, explainable and honestly benchmarked.

## Setup

```sh
bin/setup                  # deps + toolchain check + first green run
bin/console                # IRB with the API pre-loaded (ret2win facts)
```

## The rules

1. **TDD, no exceptions.** Write the failing test first (`feat:` commits ship
   their spec in the same commit). Bug fixes ship a regression test that fails
   on `main` before the fix. A PR with no test is a rejected PR.
2. **Conventional Commits, atomic.** One logical change per commit:

   ```
   feat(engine): emit rule provenance in result
   fix(facts): reject nested quotes in string atoms
   test(corpus): add protostar stack6 anti-reflex case
   docs(readme): clarify dry-run mode
   chore(ci): add bundler-audit job
   ```

   Types: `feat`, `fix`, `test`, `docs`, `chore`, `refactor`, `perf`.
   Subject <= 50 chars, imperative mood, English. Body explains *why*.
3. **Branches.** `feat/<scope>`, `fix/<scope>`, `chore/<scope>`, `docs/<scope>`
   off `main`. `main` stays green. During bootstrap we merge locally with
   `--no-ff`; pull requests with review become mandatory once the project is
   team-stable (the PR template and branch protection are ready for that day).
4. **SemVer.** Development is `0.y.z`: minor bumps may break. `1.0.0` waits for
   a stable public API. Tag releases on `main` as `vX.Y.Z` *after* the merge.
5. **CHANGELOG.md.** Every feature/fix lands in `[Unreleased]` in the same
   commit as the change. Releases move `[Unreleased]` to a dated section.
   No release without a changelog entry.
6. **Zero runtime dependencies.** The core gem ships with no runtime deps.
   External engines (Soufflé, SMT solvers, LLM providers) enter only through
   subprocess/HTTP boundaries.
7. **No exploit code, ever.** The repo encodes technique *metadata* (rules,
   facts, checks), never payloads. See the acceptable-use section in README.
8. **Claims discipline.** Benchmarks are predictions against frozen corpora,
   not field results. Do not upgrade wording ("verified" means the corpus
   agrees, nothing more).

## Lint and checks

```sh
bundle exec rspec          # all green required
bundle exec standardrb     # no offenses required
bundle exec bundler-audit  # before any release
```

## Releasing

1. Update `CHANGELOG.md`: move `[Unreleased]` to a dated section.
2. Bump `lib/augure/version.rb`.
3. `git commit -m "chore(release): v0.x.y"` then `git tag vX.Y.Z`.
4. Tag AFTER the merge lands on `main`, push tags one by one.
