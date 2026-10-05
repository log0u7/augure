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

    include Enumerable

    def self.parse(text)
      new.parse(text)
    end

    def self.from_file(path)
      parse(File.read(path))
    end

    def initialize
      @rels = {}
    end

    def parse(text)
      text.each_line.with_index(1) do |line, lineno|
        line = line.rstrip
        next if line.empty? || line.start_with?("//")

        consume(line, lineno)
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
      other_r = other.instance_variable_get(:@rels)
      SCHEMA.each_key do |name|
        combined = Array(@rels[name]) + Array(other_r[name])
        rels[name] = combined unless combined.empty?
      end
      merged
    end

    # Builder API for programmatic construction (the profiler's contract):
    # identical validation as parsing - same schema, same loud failures.
    def add(name, *args)
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
      (@rels[name] ||= []) << args
      self
    end

    def to_s
      SCHEMA.filter_map do |name, _arity|
        @rels.fetch(name, []).map { |tuple| emit_fact(name, tuple) }
      end.join
    end

    private

    def consume(line, lineno)
      raise MalformedFact, "line #{lineno}: rules are not facts, only facts belong here" if line.include?(":-")

      match = line.match(/\A([a-z][a-z0-9_]*)\((.*)\)\.\z/)
      raise MalformedFact, "line #{lineno}: malformed fact #{line.inspect}" unless match

      name = match[1]
      raw_args = match[2]
      raise UnknownPredicate, "line #{lineno}: unknown predicate #{name.inspect}" unless SCHEMA.key?(name)

      args = parse_args(raw_args, name, lineno)
      begin
        add(name, *args)
      rescue UnknownPredicate, MalformedFact => e
        raise e.class, "line #{lineno}: #{e.message}"
      end
    end

    def parse_args(raw, name, lineno)
      return [] if raw.strip.empty?

      raw.split(",", -1).map.with_index do |arg, i|
        arg = arg.strip
        if arg.match?(/\A-?\d+\z/)
          arg.to_i
        elsif arg.match?(/\A"[^"\\()]*"\z/)
          arg[1..-2]
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
