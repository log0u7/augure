# frozen_string_literal: true

module Augure
  # Forward-chaining evaluator over a rule table. Interprets the Rules data;
  # keeps, per derived head, the rule id and the evidence tuples that fired
  # it. Naive fixpoint: the rule set is tiny, clarity beats semi-naive here.
  class Engine
    Result = Struct.new(:derived_rels, :provenance_by_head) do
      def derived(rel)
        derived_rels.fetch(rel, [])
      end

      def applicable
        provenance_by_head.filter_map do |head, provs|
          head[1] if head[0] == Rules::APPLICABLE && !provs.empty?
        end
      end

      def provenance(technique)
        provenance_by_head.fetch([Rules::APPLICABLE, technique], [])
      end
    end

    OP = {lt: :<, le: :<=, gt: :>, ge: :>=, eq: :==}.freeze

    def initialize(facts, rules: nil)
      @facts = facts
      @rules = rules || Rules.all
    end

    def run
      rels = seeded_relations

      loop do
        fired = false
        @rules.each do |rule|
          head_key = [rule.head[0], rule.head[1..]]
          evidence = satisfy(rule.conditions, rels)
          next if evidence.empty?
          next if rels.key?(head_key)

          rels[head_key] = evidence
          fired = true
        end
        break unless fired
      end

      build_result(rels)
    end

    private

    # key: [rel_name, tuple]; value: evidence (tuple combos that fired it).
    # Input facts carry an empty evidence; defaults are seeded as inputs.
    def seeded_relations
      rels = {}
      @facts.each { |(name, tuple)| rels[[name, tuple]] = [] }
      Rules::DEFAULTS.each do |name, default|
        rels[[name, [default]]] ||= [] if @facts.rel(name).nil?
      end
      rels
    end

    def tuples_for(rels, rel)
      rels.filter_map { |(r, t), _| t if r == rel }
    end

    # Returns combos of evidence items ([rel, atom, ...] pairs) when
    # satisfiable, [] else. A negated condition contributes an empty item.
    def satisfy(conditions, rels)
      combos = [[]]
      conditions.each do |cond|
        hits = match_condition(cond, rels)
        return [] if hits.empty?

        combos = combos.flat_map { |c| hits.map { |h| c + [h] } }
      end
      combos
    end

    def match_condition(cond, rels)
      case cond[0]
      when :fact
        tuples_for(rels, cond[1])
          .select { |t| t == [cond[2]] }
          .map { |t| [cond[1], t[0]] }
      when :not_fact
        present = tuples_for(rels, cond[1]).any? { |t| t == [cond[2]] }
        present ? [] : [[]]
      when :match
        pattern = /#{cond[3]}/
        tuples_for(rels, cond[1])
          .select { |t| t[cond[2]].is_a?(String) && t[cond[2]] =~ pattern }
          .map { |t| [cond[1], *t] }
      when :cmp
        tuples_for(rels, cond[1])
          .select { |t| t[0].is_a?(Integer) && t[0].public_send(OP.fetch(cond[2]), cond[3]) }
          .map { |t| [cond[1], *t] }
      else
        raise EngineError, "unknown condition #{cond[0].inspect}"
      end
    end

    def build_result(rels)
      derived = {}
      provs = {}
      rels.each do |(r, t), evidence|
        # Pure input facts (empty evidence) never surface as derived outputs.
        next if evidence.empty?

        (derived[r] ||= []) << t
        key = [r, t[0]]
        entries = provs[key] ||= []
        evidence.each do |combo|
          entries << {rule: rule_for(key), evidence: combo.reject(&:empty?)}
        end
      end
      Result.new(derived, provs)
    end

    def rule_for(head_key)
      @rules.find { |r| r.head == head_key }&.id
    end
  end
end
