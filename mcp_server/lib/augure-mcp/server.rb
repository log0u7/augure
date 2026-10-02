# frozen_string_literal: true

require "mcp"
require "augure"

module AugureMcp
  # The MCP surface of the decision layer: READ-ONLY by design. The server
  # executes nothing - it is the SDK boundary. An LLM that asks "which
  # technique?" gets a verified, explained decision instead of a guess.
  class Server
    TOOLS = [
      AnalyzeTarget = Class.new(MCP::Tool) do
        description "Analyze an augure fact file (or raw facts) and return the " \
                    "auditable decision: applicable techniques, verified checks, " \
                    "deterministic ranking, seeded selection, plan and the full " \
                    "provenance (rule IDs + evidence). Read-only; executes nothing."
        input_schema(
          properties: {
            facts: {type: "string", description: "Raw facts text (predicate lines)"},
            facts_file: {type: "string", description: "Path to a .facts file"},
            seed: {type: "integer", description: "Optional seed for reproducible draws"}
          }
        )

        class << self
          def call(facts: nil, facts_file: nil, seed: nil, server_context: nil)
            text = facts || (facts_file && File.read(facts_file))
            return MCP::Tool::Response.new([{type: "text", text: "error: provide facts or facts_file"}]) unless text

            result = ::Augure::Pipeline.analyze(facts: text, seed: seed ? Integer(seed) : nil)
            MCP::Tool::Response.new([{type: "text", text: JSON.pretty_generate(
              applicable: result[:applicable],
              verified: result[:verified],
              ranking: result[:ranking],
              selected: result[:selected],
              plan: result[:plan],
              explain: result[:explain]
            )}])
          rescue ::Augure::MalformedFact, ::Augure::UnknownPredicate => e
            MCP::Tool::Response.new([{type: "text", text: "error: #{e.message}"}])
          end
        end
      end,

      ListRules = Class.new(MCP::Tool) do
        description "List the augure rules-as-data table: rule IDs, heads and " \
                    "documented sources. The single source of truth for " \
                    "technique applicability."
        input_schema(properties: {})

        class << self
          def call(server_context: nil)
            rows = ::Augure::Rules.all.map do |rule|
              {id: rule.id, head: rule.head.join("="), source: rule.source}
            end
            MCP::Tool::Response.new([{type: "text", text: JSON.pretty_generate(rules: rows)}])
          end
        end
      end,

      ExplainTechnique = Class.new(MCP::Tool) do
        description "Explain one technique: its rule conditions and documented " \
                    "knowledge-base entry (pattern, chain, unlocks, success rate)."
        input_schema(
          properties: {technique: {type: "string"}},
          required: ["technique"]
        )

        class << self
          def call(technique:, server_context: nil)
            rules = ::Augure::Rules.all.select { |r| r.head == [::Augure::Rules::APPLICABLE, technique] }
            entries = ::Augure::KnowledgeBase.corpus.select { |e| e["technique"] == technique }
            MCP::Tool::Response.new([{type: "text", text: JSON.pretty_generate(
              technique: technique,
              rules: rules.map { |r| {id: r.id, source: r.source} },
              knowledge: entries
            )}])
          end
        end
      end
    ].freeze

    def self.build
      ::MCP::Server.new(name: "augure-mcp", version: "0.1.0", tools: TOOLS).tap do |server|
        server.instructions = "augure is an auditable exploitation decision layer. " \
                              "Use analyze_target on fact files; every answer ships " \
                              "its rule provenance. Augure decides, it never executes."
      end
    end
  end
end
