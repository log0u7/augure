# frozen_string_literal: true

require "yaml"

module Augure
  # A technique pack: ONE new technique, complete, as DATA - rules, KB
  # entries, MCTS transitions and priors. Written by an operator or an
  # agent; validated here before it can influence anything.
  #
  # The armor (in load order):
  #   1. constrained condition vocabulary (fact/not_fact/match/cmp)
  #   2. conditions reference EXISTING predicates only (facts schema +
  #      built-in derived heads) - a pack cannot invent a fact source
  #   3. stratification: negation on input facts only
  #   4. new heads only: a pack never overrides a built-in technique
  #   5. provenance is mandatory (author + source)
  #   6. the corpus guard runs in PackLoader (belt and braces on 4)
  class Pack
    CONDITION_VOCABULARY = %w[fact not_fact match cmp].freeze

    attr_reader :technique, :author, :source, :rules, :kb, :mcts, :priors, :build, :detection, :mitre

    def self.load_file(path)
      data = YAML.safe_load_file(path, permitted_classes: [], aliases: false)
      raise PackError, "#{path}: invalid YAML" unless data.is_a?(Hash)

      load_hash(data)
    end

    def self.load_hash(data)
      new(data)
    end

    def initialize(data)
      @data = data
      validate_shape
      build
    end

    private

    def reject(message)
      raise PackError, "#{technique_name || "pack"}: #{message}"
    end

    def technique_name
      @data["technique"]
    end

    def validate_shape
      @technique = @data["technique"]
      unless @technique.is_a?(String) && @technique.match?(/\A[a-z0-9_]+\z/)
        reject "technique name must match [a-z0-9_]+"
      end

      @author = @data["author"]
      reject "author is mandatory (provenance is not optional)" unless @author.is_a?(String) && !@author.empty?
      @source = @data["source"]
      unless @source.is_a?(String) && !@source.empty?
        reject "source is mandatory (write-up URL, ticket, anything verifiable)"
      end

      validate_rules(@data["rules"])
      validate_kb(@data["kb"])
      validate_mcts(@data["mcts"])
      validate_priors(@data["priors"])
      validate_build(@data["build"])
      validate_detection(@data["detection"])
      validate_mitre(@data["mitre"])
      build_rules
    end

    def known_predicates
      @known_predicates ||= Facts::SCHEMA.keys + Rules.all.reject { |r| r.head[0] == Rules::APPLICABLE }.map { |r| r.head[0] }
    end

    def input_predicates
      Facts::SCHEMA
    end

    def built_in_techniques
      @built_in_techniques ||= Rules.applicable_rules.map { |r| r.head[1] }
    end

    def validate_rules(rules)
      reject "rules are mandatory" unless rules.is_a?(Array) && !rules.empty?

      rules.each_with_index do |rule, i|
        reject "rule #{i}: id mandatory" unless rule["id"].is_a?(String)
        head = rule["head"]
        unless head.is_a?(Array) && head[0] == Rules::APPLICABLE && head[1] == @technique
          reject "rule #{i}: head must be [applicable, <technique>]"
        end
        if built_in_techniques.include?(head[1])
          reject "head overrides a built-in technique (#{head[1]}) - new techniques only"
        end

        conditions = rule["conditions"]
        reject "rule #{i}: conditions mandatory" unless conditions.is_a?(Array) && !conditions.empty?
        conditions.each_with_index do |cond, j|
          validate_condition(cond, "rule #{i} condition #{j}")
        end
      end
    end

    def validate_condition(cond, label)
      unless cond.is_a?(Array) && CONDITION_VOCABULARY.include?(cond[0])
        reject "#{label}: #{cond.inspect} is outside the condition vocabulary #{CONDITION_VOCABULARY.inspect}"
      end

      kind = cond[0]
      rel = cond[1]
      if kind == "not_fact"
        unless input_predicates.key?(rel)
          reject "#{label}: not_fact on #{rel.inspect} breaks stratification (negation on input facts only)"
        end
      elsif kind == "cmp"
        reject "#{label}: cmp needs [cmp, rel, op, n]" unless cond.size == 4
        reject "#{label}: unknown predicate #{rel.inspect}" unless input_predicates.key?(rel)
        unless Engine::OP.key?(cond[2].to_sym)
          reject "#{label}: cmp operator #{cond[2].inspect} unknown (#{Engine::OP.keys.join(", ")})"
        end
        unless cond[3].is_a?(Integer)
          reject "#{label}: cmp operand #{cond[3].inspect} must be an integer (the engine compares integer fact values)"
        end
      elsif kind == "match"
        reject "#{label}: match pattern #{cond[3].inspect} must be a string" unless cond[3].is_a?(String)
        begin
          Regexp.new(cond[3])
        rescue RegexpError => e
          reject "#{label}: match pattern #{cond[3].inspect} is not a valid regex (#{e.message})"
        end
      else
        reject "#{label}: unknown predicate #{rel.inspect}" unless known_predicates.include?(rel)
      end
    end

    def validate_kb(entries)
      reject "kb entries mandatory (the knowledge IS the technique)" unless entries.is_a?(Array) && !entries.empty?
      entries.each_with_index do |e, i|
        reject "kb #{i}: id mandatory" unless e["id"].is_a?(String)
        rate = e["success_rate"]
        reject "kb #{i}: success_rate must be a number in [0, 1]" unless rate.is_a?(Numeric) && rate.between?(0, 1)
        reject "kb #{i}: description mandatory" unless e["description"].is_a?(String) && !e["description"].empty?
      end
    end

    def validate_mcts(mcts)
      reject "mcts transitions mandatory" unless mcts.is_a?(Hash)
      %w[requires provides].each do |k|
        reject "mcts.#{k} must be an array" unless mcts[k].is_a?(Array)
      end
      reject "mcts.terminal must be true or false" unless [true, false].include?(mcts["terminal"])
      reject "mcts.success must be a number in [0, 1]" unless mcts["success"].is_a?(Numeric) && mcts["success"].between?(
        0, 1
      )
    end

    def validate_priors(priors)
      return if priors.is_a?(Array) && priors.size == 2 && priors.all?(Numeric)

      reject "priors must be [alpha, beta] (two numbers)"
    end

    # armor check 8: the optional build: section (the pack teaching the
    # BUILDER its assembly order) must name its own technique and use
    # the slot vocabulary only. The consumer (lictor's PayloadBuilder)
    # interprets the slots; here we gate the vocabulary.
    BUILD_SLOTS = %w[padding qword dword shellcode chain].freeze

    # armor check 9: the optional detection: section - the DEFENDER
    # side of the technique (the corpus read backwards). Constrained
    # channel vocabulary; every entry carries a signature and a note -
    # a vague hint is not detection content.
    DETECTION_CHANNELS = %w[wire syslog syscall crash file].freeze

    def validate_detection(detection)
      return if detection.nil?

      unless detection.is_a?(Array) && !detection.empty?
        reject "detection: must be a non-empty array"
      end
      detection.each_with_index do |e, i|
        unless e.is_a?(Hash) && DETECTION_CHANNELS.include?(e["channel"])
          reject "detection #{i}: channel must be from #{DETECTION_CHANNELS.inspect}"
        end
        %w[signature note].each do |field|
          unless e[field].is_a?(String) && !e[field].empty?
            reject "detection #{i}: #{field} is mandatory (a vague hint is not detection content)"
          end
        end
      end
      @detection = detection
    end

    # armor check 10: the optional mitre: mapping - ATT&CK technique
    # codes (T####[.###]); the export layer (rules --mitre) consumes it.
    MITRE_CODE = /\AT\d{4}(?:\.\d{3})?\z/

    def validate_mitre(mitre)
      return if mitre.nil?

      unless mitre.is_a?(Array) && !mitre.empty? && mitre.all? { |c| c.is_a?(String) && c.match?(MITRE_CODE) }
        reject "mitre: must be an array of ATT&CK technique codes (T1068, T1068.001)"
      end
      @mitre = mitre
    end

    def validate_build(build)
      return if build.nil?

      unless build.is_a?(Hash) && build["technique"] == @technique
        reject "build: must name its own technique (#{build.is_a?(Hash) ? build["technique"].inspect : "missing"})"
      end
      layout = build["layout"]
      unless layout.is_a?(Array) && !layout.empty? &&
          layout.all? { |slot| slot.is_a?(Array) && BUILD_SLOTS.include?(slot[0]) }
        reject "build: layout must be a non-empty array of slots from #{BUILD_SLOTS.inspect}"
      end
      @build = build
    end

    def build_rules
      @rules = @data["rules"].map do |rule|
        conditions = rule["conditions"].map do |cond|
          normalized = cond.map do |v|
            if v == true then "true"
            elsif v == false then "false"
            else v
            end
          end
          [normalized[0].to_sym, *normalized[1..]]
        end
        Rules::Rule.new(
          id: rule["id"].to_sym, head: rule["head"], conditions: conditions,
          source: "#{@data["source"]} (pack #{@technique} by #{@author})", origin: @technique
        )
      end
      @kb = @data["kb"]
      @mcts = @data["mcts"]
      @priors = @data["priors"].map(&:to_f)
    end
  end
end
