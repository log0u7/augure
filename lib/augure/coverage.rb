# frozen_string_literal: true

module Augure
  # The corpus read backwards (the defender side): re-decide every
  # entry against a HARDENED fact set and report which techniques die,
  # which survive. The auditability doc's "the model read backwards"
  # as a command: flip nx/relro/canary/pie, watch the rules die, and
  # the remaining applicable techniques are the attacker's next moves.
  module Coverage
    module_function

    # entries: corpus-shaped ({suite:, name:, facts:}). flips: {predicate
    # => value-or-nil} - a value REPLACES every existing fact of that
    # predicate (hardening is an override); nil REMOVES them (the
    # speculative turn-off).
    def report(entries, flips:, priors: nil)
      priors ||= Pipeline.default_priors
      out = {entries: [], died: {}, gained: {}, survived_count: 0}
      Array(entries).each do |entry|
        facts = Facts.parse(entry["facts"])
        before = Pipeline.analyze(facts: facts, priors: priors, plan: false)[:applicable]
        hardened = with_flips(facts, flips)
        after = Pipeline.analyze(facts: hardened, priors: priors, plan: false)[:applicable]
        lost = before - after
        found = after - before
        lost.each { |t| out[:died][t] = out[:died].fetch(t, 0) + 1 }
        found.each { |t| out[:gained][t] = out[:gained].fetch(t, 0) + 1 }
        out[:survived_count] += 1 if before == after
        out[:entries] << {suite: entry["suite"], name: entry["name"], before: before,
                          after: after, lost: lost, gained: found,
                          hardened_facts: hardened.to_s}
      end
      out
    end

    # Replace-or-remove every fact of a flipped predicate. The flip is
    # the HARDENING decision: one value per predicate, decided by the
    # operator, not appended noise.
    def with_flips(facts, flips)
      return facts if flips.nil? || flips.empty?

      dropped = Facts.new
      kept = Facts.new
      facts.each do |(name, tuple)|
        (flips.key?(name) ? dropped : kept).add(name, *tuple)
      end
      flips.each do |name, value|
        next if value.nil?

        arity = Facts::SCHEMA.fetch(name)
        kept.add(name, *([value] * arity))
      end
      kept
    end
  end
end
