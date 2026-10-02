# frozen_string_literal: true

module Augure
  # The pipeline facade: facts -> engine -> bandit -> MCTS -> decision.
  # Augure decides; it never executes. The returned hash is the audit
  # payload: applicable, verified, selected, plan and the per-technique
  # rule provenance.
  module Pipeline
    module_function

    def analyze(facts:, seed: nil, priors: nil, solver: nil, buffer_size: 256)
      facts = Facts.parse(facts) if facts.is_a?(String)
      engine_result = Engine.new(facts).run
      applicable = engine_result.applicable

      verified = verify(applicable, facts: facts, solver: solver, buffer_size: buffer_size)

      bandit = selector(priors: priors)
      selected = bandit.select(verified.keys.empty? ? applicable : verified.keys)
      plan = plan_for(applicable, seed: seed)

      {
        applicable: applicable,
        verified: verified,
        selected: selected,
        plan: plan,
        explain: {provenance: engine_result.provenance_by_head
          .select { |head, _| head[0] == Rules::APPLICABLE }
          .transform_keys { |head| head[1] }
          .transform_values { |provs| provs.map { |p| {rule: p[:rule], evidence: p[:evidence]} } }}
      }
    end

    # The selector every consumer shares: AG inversions + KB-informed priors.
    def selector(priors: nil)
      Bandit.new(priors: priors || default_priors)
    end

    def default_priors
      @default_priors ||= begin
        merged = AG_PRIORS.transform_values(&:dup)
        KnowledgeBase.priors.each do |tech, (a, b)|
          merged[tech] = if merged[tech]
            [merged[tech][0] + a, merged[tech][1] + b]
          else
            [a, b]
          end
        end
        merged
      end
    end

    def verify(applicable, facts:, solver:, buffer_size:)
      applicable.each_with_object({}) do |tech, out|
        checks = {}
        checks[:payload_fits] = Verifier.payload_fits(buffer_size: buffer_size, payload_min: 40)
        out[tech] = {status: (checks.values.all? { |s| s == :sat }) ? :sat : :unsat, checks: checks}
      end
    end

    def plan_for(applicable, seed:)
      return [] if applicable.empty?

      _first, path = Mcts.plan(applicable, iterations: 2000, seed: seed || 42)
      path
    end
  end
end
