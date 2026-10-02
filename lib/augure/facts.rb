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
      "remote" => 1
    }.freeze

    STRING_TYPES = {
      "gadget" => %w[string integer],
      "glibc_minor" => %w[integer]
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
      unless SCHEMA.key?(name)
        raise UnknownPredicate, "unknown predicate #{name.inspect}"
      end

      arity = SCHEMA[name]
      unless args.size == arity
        raise MalformedFact, "#{name} expects arity #{arity}, got #{args.size}"
      end

      check_types(name, args, 0)
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
      if line.include?(":-")
        raise MalformedFact, "line #{lineno}: rules are not facts, only facts belong here"
      end

      match = line.match(/\A([a-z][a-z0-9_]*)\((.*)\)\.\z/)
      unless match
        raise MalformedFact, "line #{lineno}: malformed fact #{line.inspect}"
      end

      name, raw_args = match[1], match[2]
      unless SCHEMA.key?(name)
        raise UnknownPredicate, "line #{lineno}: unknown predicate #{name.inspect}"
      end

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
      args = tuple.each_with_index.map { |arg, i|
        (types && types[i] == "integer") ? arg.to_s : %("#{arg}")
      }
      "#{name}(#{args.join(", ")}).\n"
    end
  end
end
