# frozen_string_literal: true

module Augure
  # Strict, schema-checked parser for Augure fact files.
  #
  # A fact is one line: predicate("string").  or  predicate("atom", 42).
  # The schema is the single source of truth for which predicates exist and
  # their arity. Anything else is rejected with an explicit error: silent
  # acceptance of malformed input is what broke the Python prototype.
  class Facts
    # name => arity. Order is the emission order of #to_s.
    SCHEMA = {
      "nx" => 1, "pie" => 1, "canary" => 1, "relro" => 1,
      "plt" => 1, "gadget" => 2, "vuln_hint" => 1, "vuln" => 1,
      "target_function" => 1, "libc_present" => 1, "allocator" => 1,
      "glibc_minor" => 1, "return_addr_filtered" => 1,
      "got_overwrite_target" => 1, "function_pointer_on_heap" => 1,
      "seccomp" => 1, "shellcode_input" => 1, "sigreturn_frame" => 1,
      "fmtstr_read" => 1, "reloc_writable" => 1, "dt_lazy" => 1,
      "limited_stack" => 1, "service" => 1, "software_version" => 1,
      "remote" => 1, "verified" => 1, "win_symbol" => 2,
      "crash_site" => 1, "vuln_function" => 1, "sink" => 1, "leaked_address" => 2,
      "plt_addr" => 2, "got_addr" => 2, "cve" => 1
    }.freeze

    STRING_TYPES = {
      "gadget" => %w[string integer],
      "win_symbol" => %w[string integer],
      "crash_site" => %w[string],
      "vuln_function" => %w[string],
      "sink" => %w[string],
      "leaked_address" => %w[string integer],
      "plt_addr" => %w[string integer],
      "got_addr" => %w[string integer],
      "glibc_minor" => %w[integer],
      "cve" => %w[string]
    }.freeze

    # Closed value domains: a typo'd atom ("ture", "maybe") would parse,
    # disable the closed-world default, and every rule of the predicate
    # would silently never fire. The loud-failure philosophy stops at
    # the grammar AND the vocabulary.
    VALUE_DOMAINS = {
      "nx" => %w[true false], "pie" => %w[true false], "canary" => %w[true false],
      "relro" => %w[none partial full], "target_function" => %w[true false],
      "libc_present" => %w[true false], "function_pointer_on_heap" => %w[true false],
      "got_overwrite_target" => %w[true false], "seccomp" => %w[true false],
      "shellcode_input" => %w[true false], "sigreturn_frame" => %w[true false],
      "fmtstr_read" => %w[true false], "reloc_writable" => %w[true false],
      "dt_lazy" => %w[true false], "limited_stack" => %w[true false],
      "remote" => %w[true false], "verified" => %w[remote],
      "return_addr_filtered" => %w[true false]
    }.freeze

    # Hard cap on suggested facts accepted in one merge (P1): the
    # measured brainforge pilot emitted 802 facts for one target. The
    # cap is overridable per call; overflow is named loudly, never
    # silently truncated.
    SUGGEST_CAP = 16

    # The on-disk provenance marker (P3): serialization of a suggested-only
    # fact. The marker can only ever mark a fact as the WEAKER class, so a
    # hostile hand-edited line can close a gate, never open one.
    SUGGESTED_MARKER_RE = %r{\s*//\s*suggested\z}

    include Enumerable

    def self.parse(text)
      new.parse(text)
    end

    def self.from_file(path)
      parse(File.read(path))
    end

    def initialize
      @rels = {}
      @sources = {}
    end

    def parse(text)
      text.each_line.with_index(1) do |line, lineno|
        line = line.rstrip
        # the P3 marker travels WITH the fact line: strip it and tag the
        # fact as the weaker provenance class before grammar validation
        suggested = !line.sub!(SUGGESTED_MARKER_RE, "").nil?
        line = line.rstrip
        next if line.empty? || line.start_with?("//")

        consume(line, lineno, source: suggested ? :suggested : :measured)
      end
      self
    end

    def rel(name)
      @rels[name]&.dup
    end
    alias_method :[], :rel

    def each
      SCHEMA.each_key do |name|
        @rels.fetch(name, []).each { |tuple| yield([name, tuple]) }
      end
    end

    def size
      @rels.values.sum(&:size)
    end

    def merge(other)
      merged = self.class.new
      rels = merged.instance_variable_get(:@rels)
      sources = merged.instance_variable_get(:@sources)
      other_r = other.instance_variable_get(:@rels)
      other_s = other.instance_variable_get(:@sources)
      SCHEMA.each_key do |name|
        combined = Array(@rels[name]) + Array(other_r[name])
        next if combined.empty?

        rels[name] = combined
        combined.each do |tuple|
          key = [name, tuple]
          own = Array(@sources[key])
          ext = Array(other_s[key])
          sources[key] = (own + ext).uniq unless own.empty? && ext.empty?
        end
      end
      merged
    end

    # The LLM suggest merge path (P1): deduplicate identical lines
    # preserving first-emission order, cap the accepted suggested facts
    # at +cap+, and warn loudly on every rejection. A line repeating a
    # fact the store already carries is a duplicate (its provenance IS
    # recorded - the profiler and the suggest step agreed - but it does
    # not consume the cap).
    #
    # @param text [String] raw suggestion fact lines
    # @param cap [Integer] hard cap on accepted suggested facts
    # @param warn [#call] warning sink (default: $stderr)
    # @return [Hash] {accepted:, duplicates:, dropped:}
    def merge_suggested(text, cap: SUGGEST_CAP, warn: $stderr.method(:puts))
      accepted = 0
      duplicates = 0
      dropped = 0
      text.each_line.with_index(1) do |line, lineno|
        line = line.rstrip
        next if line.empty? || line.start_with?("//")

        name, args = parse_line(line, lineno)
        if @rels[name]&.include?(args)
          # duplicate line: record the provenance (both classes agree)
          # without storing another tuple
          sources = (@sources[[name, args]] ||= [])
          sources << :suggested unless sources.include?(:suggested)
          duplicates += 1
          dropped += 1
        elsif accepted >= cap
          dropped += 1
        else
          begin
            add(name, *args, source: :suggested)
          rescue UnknownPredicate, MalformedFact => e
            raise e.class, "line #{lineno}: #{e.message}"
          end
          accepted += 1
        end
      end

      if dropped.positive?
        warn.call "augure: suggest merge dropped #{dropped} fact(s) " \
                  "(cap #{cap}, accepted #{accepted}, duplicates #{duplicates}); " \
                  "trim the suggestion stream or raise the cap explicitly."
      end
      {accepted: accepted, duplicates: duplicates, dropped: dropped}
    end

    # Builder API for programmatic construction (the profiler's contract):
    # identical validation as parsing - same schema, same loud failures.
    # Every fact carries its provenance class: the profiler/harvest path
    # emits measured facts (default), the LLM suggest path emits
    # suggested facts. The class is recorded in a parallel registry and
    # reported by #source_of, so a decision can be audited against what
    # the binary actually showed versus what the model claimed.
    def add(name, *args, source: :measured)
      raise UnknownPredicate, "unknown predicate #{name.inspect}" unless SCHEMA.key?(name)

      arity = SCHEMA[name]
      raise MalformedFact, "#{name} expects arity #{arity}, got #{args.size}" unless args.size == arity

      check_types(name, args, 0)
      domain = VALUE_DOMAINS[name]
      if domain && args.size == 1 && args.first.is_a?(String) && !domain.include?(args.first)
        raise MalformedFact, "#{name}: value #{args.first.inspect} is outside the value domain #{domain.inspect}"
      end

      # the atom grammar is the load-bearing wall: a symbol name from an
      # untrusted binary (win_symbol) or a version string from a hostile
      # banner (software_version) must not carry quotes, backslashes,
      # parens or newlines into a re-parsed facts file
      args.each do |arg|
        next unless arg.is_a?(String) && arg.match?(/["\\()\n\r]/)

        raise MalformedFact, "#{name}: fact atoms may not contain quotes, backslashes, parens or newlines"
      end
      # the empty atom: a fact like allocator("") carries no observation -
      # it parses, then every rule of the predicate silently never fires
      # (measured: the suggest step's empty allocator tilted a decision).
      # Loud failure instead of silent void.
      args.each do |arg|
        next unless arg.is_a?(String) && arg.empty?

        raise MalformedFact, "#{name}: fact atoms may not be empty strings"
      end
      (@rels[name] ||= []) << args
      (@sources[[name, args]] ||= []) << source unless @sources[[name, args]]&.include?(source)
      self
    end

    # The provenance classes recorded for one fact (e.g. %i[measured]),
    # in the order the sources entered the store.
    def source_of(name, *args)
      @sources[[name, args]] || []
    end

    # True when the profiler/harvest path (not just the LLM suggest)
    # produced this fact - the corroboration precondition tests rest on it.
    def measured?(name, *args)
      @sources[[name, args]]&.include?(:measured)
    end

    def to_s
      SCHEMA.filter_map do |name, _arity|
        @rels.fetch(name, []).map do |tuple|
          sources = @sources[[name, tuple]] || []
          line = emit_fact(name, tuple)
          next line if sources.include?(:measured) || !sources.include?(:suggested)

          line.sub(/\n\z/, " // suggested\n")
        end
      end.join
    end

    private

    # Pure parsing: validates the grammar, vocabulary and atoms of one
    # fact line and returns [name, args] without touching the store.
    # Both #consume and #merge_suggested go through this, so the
    # suggest path enforces the exact same loud failures.
    def parse_line(line, lineno)
      raise MalformedFact, "line #{lineno}: rules are not facts, only facts belong here" if line.include?(":-")

      match = line.match(/\A([a-z][a-z0-9_]*)\((.*)\)\.\z/)
      raise MalformedFact, "line #{lineno}: malformed fact #{line.inspect}" unless match

      name = match[1]
      raw_args = match[2]
      raise UnknownPredicate, "line #{lineno}: unknown predicate #{name.inspect}" unless SCHEMA.key?(name)

      args = parse_args(raw_args, name, lineno)
      arity = SCHEMA[name]
      raise MalformedFact, "line #{lineno}: #{name} expects arity #{arity}, got #{args.size}" unless args.size == arity

      begin
        # dry-run validation: schema, arity, types and domains without
        # storing anything - so the cap/dedupe decisions in
        # #merge_suggested are made on a fact that will actually parse.
        check_types(name, args, lineno)
      rescue MalformedFact => e
        raise e.class, "line #{lineno}: #{e.message.sub(/\Aline \d+: /, "")}"
      end
      [name, args]
    end

    def consume(line, lineno, source: :measured)
      name, args = parse_line(line, lineno)
      add(name, *args, source: source)
    end

    def parse_args(raw, name, lineno)
      return [] if raw.strip.empty?

      raw.split(",", -1).map.with_index do |arg, i|
        arg = arg.strip
        if arg.match?(/\A-?\d+\z/)
          arg.to_i
        elsif arg.match?(/\A"[^"\\()]*"\z/)
          inner = arg[1..-2]
          if inner.empty?
            raise MalformedFact,
              "line #{lineno}: #{name} arg #{i + 1} may not be an empty string"
          end

          inner
        else
          raise MalformedFact,
            "line #{lineno}: #{name} arg #{i + 1} is not a quoted string atom or integer"
        end
      end
    end

    def check_types(name, args, lineno)
      types = STRING_TYPES[name] || (["string"] * SCHEMA[name])

      args.each_with_index do |arg, i|
        expected = types[i]
        actual = arg.is_a?(Integer) ? "integer" : "string"
        next if actual == expected

        raise MalformedFact, "line #{lineno}: #{name} arg #{i + 1} must be a #{expected} atom, got #{actual}"
      end
    end

    def emit_fact(name, tuple)
      types = STRING_TYPES[name]
      args = tuple.each_with_index.map do |arg, i|
        (types && types[i] == "integer") ? arg.to_s : %("#{arg}")
      end
      "#{name}(#{args.join(", ")}).\n"
    end
  end
end
