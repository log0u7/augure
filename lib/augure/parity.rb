# frozen_string_literal: true

module Augure
  # Static-parity contract: what the frozen corpus claims about a
  # documented target vs what the profiler observed on the REAL binary.
  # The corpus stays the write-up ground truth; parity asserts only what
  # static ELF analysis can derive, and reports honestly what it cannot:
  # gadget types outside the profiler's pattern set and source-level
  # hints (a gets() the binary never imports) are SKIPPED, not failed.
  class ParityResult
    attr_reader :target, :missing, :skipped, :checked

    def initialize(target, missing, skipped, checked)
      @target = target
      @missing = missing
      @skipped = skipped
      @checked = checked
    end

    def ok? = missing.empty?
  end

  module Parity
    EXACT_RELATIONS = %w[nx pie canary relro].freeze
    SUBSET_RELATIONS = %w[plt target_function].freeze

    module_function

    # observed: a Facts object or a facts string (main binary + shipped
    # libraries merged by the caller). entry: a corpus hash with "name"
    # and "facts". supported_gadget_types: the byte-pattern vocabulary of
    # the profiler at hand (passed in, so this core class stays
    # profiler-agnostic).
    def check(observed, entry, supported_gadget_types:)
      observed = Facts.parse(observed) if observed.is_a?(String)
      claimed = Facts.parse(entry.fetch("facts"))
      missing = []
      skipped = []
      checked = 0

      claimed.each do |rel, tuple|
        case rel
        when *EXACT_RELATIONS, *SUBSET_RELATIONS
          checked += 1
          missing << [rel, tuple] unless observed[rel]&.include?(tuple)
        when "gadget"
          if supported_gadget_types.include?(tuple[0])
            checked += 1
            missing << [rel, tuple] unless observed[rel]&.any? { |t| t[0] == tuple[0] }
          else
            skipped << [rel, tuple]
          end
        when "vuln_hint"
          sym = tuple[0].delete_prefix("unsafe_func:")
          if observed["plt"]&.any? { |t| t == [sym] }
            checked += 1
            missing << [rel, tuple] unless observed[rel]&.include?(tuple)
          else
            skipped << [rel, tuple]
          end
        else
          skipped << [rel, tuple]
        end
      end

      ParityResult.new(entry["name"], missing, skipped, checked)
    end
  end
end
