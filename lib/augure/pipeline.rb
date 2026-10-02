# frozen_string_literal: true

module Augure
  # The pipeline facade: facts -> engine -> bandit -> MCTS -> decision.
  # Augure decides; it never executes. The returned hash is the audit
  # payload: applicable, verified, selected, plan and the per-technique
  # rule provenance.
  module Pipeline
    module_function

    # Decide on a fact base and return the auditable decision.
    #
    # @param facts [String, Facts] raw fact text or a parsed fact base
    # @param seed [Integer, nil] seed for deterministic bandit/MCTS draws
    # @param priors [Hash{String => [Numeric, Numeric]}, nil] prior table
    #   overriding the AG+EXTENDED+KB defaults (see Priors.from_trail
    #   usage in lictor for the closed loop)
    # @param solver [String, nil] optional SMT solver binary for the SMT path
    # @param buffer_size [Integer] stack budget for payload-fit checks
    # @return [Hash] the decision:
    #   {applicable:, verified:, ranking:, selected:, plan:, explain:}
    #   The --json payload is the same hash stamped with
    #   "schema": "augure/decision@1" (stable contract).
    def analyze(facts:, seed: nil, priors: nil, solver: nil, buffer_size: 256, packs: nil)
      facts = Facts.parse(facts) if facts.is_a?(String)
      engine_rules = packs ? Rules.all + packs.flat_map(&:rules) : Rules.all
      effective_priors = priors || PackLoader.priors_with(packs, default_priors)
      engine_result = Engine.new(facts, rules: engine_rules).run
      applicable = engine_result.applicable

      verified = verify(applicable, facts: facts, solver: solver, buffer_size: buffer_size)

      bandit = selector(priors: effective_priors)
      ranking = bandit.ranking_of(applicable)
      candidates = verified.select { |_, v| v[:status] == :sat }.keys
      selected = bandit.select(candidates.empty? ? applicable : candidates)
      plan = plan_for(applicable, seed: seed, packs: packs)

      {
        applicable: applicable,
        verified: verified,
        ranking: ranking.map(&:first),
        selected: selected,
        plan: plan,
        explain: {provenance: engine_result.provenance_by_head
          .select { |head, _| head[0] == Rules::APPLICABLE }
          .transform_keys { |head| head[1] }
          .transform_values { |provs| provs.map { |p| {rule: p[:rule], evidence: p[:evidence], origin: p[:origin]} } }}
      }
    end

    # The selector every consumer shares: AG inversions + KB-informed priors.
    def selector(priors: nil)
      Bandit.new(priors: priors || default_priors)
    end

    def default_priors
      @default_priors ||= begin
        # Disjoint by design: EXTENDED_PRIORS covers techniques the AG
        # simulation never scored.
        merged = AG_PRIORS.merge(EXTENDED_PRIORS)
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

    def plan_for(applicable, seed: nil, packs: nil)
      return [] if applicable.empty?

      model = packs ? Mcts.merged_model(packs) : Mcts::STAGE_MODEL
      _first, path = Mcts.plan(applicable, iterations: 2000, seed: seed || 42, model: model)
      path
    end
  end
end
