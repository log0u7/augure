# frozen_string_literal: true

require "open3"

module AugureProfiler
  # Input fuzzing: mutate a seed, deliver to the target's stdin, detect
  # crashes by signal. The built-in RubyMutator is zero-dependency and
  # covers CTF-grade discovery; radamsa (subprocess) upgrades the
  # mutation quality when installed. This is the fact DISCOVERY layer
  # for binaries that have no write-up.
  class TriageError < StandardError; end

  module RubyMutator
    BOUNDARY_BYTES = ["\x00".b, "\xff".b, "\x80".b, "\n".b, "%n".b].freeze

    module_function

    def mutate(seed, count, rng, max_len: 256)
      (0...count).map do
        variant = apply_one_mutation(seed.dup, rng)
        variant = variant[0, max_len]
        variant << ("A" * 8) if variant.empty?
        variant
      end
    end

    def apply_one_mutation(input, rng)
      case rng.rand(4)
      when 0 then bit_flip(input, rng)
      when 1 then repeat_chunk(input, rng)
      when 2 then inject_boundary(input, rng)
      else extend_pattern(input, rng)
      end
    end

    def bit_flip(input, rng)
      return input if input.empty?

      i = rng.rand(input.bytesize)
      input.setbyte(i, input.getbyte(i) ^ (1 << rng.rand(8)))
      input
    end

    def repeat_chunk(input, rng)
      return input if input.empty?

      at = rng.rand(input.bytesize)
      len = [rng.rand(input.bytesize) + 1, 16].min
      input.insert(at, input[at, len] * 2)
    end

    def inject_boundary(input, rng)
      at = rng.rand(input.bytesize + 1)
      input.insert(at, BOUNDARY_BYTES[rng.rand(BOUNDARY_BYTES.size)])
    end

    # The classic: grow with the cyclic pattern - offsets become readable
    # in the crash report.
    def extend_pattern(input, rng)
      growth = "A" * (8 + rng.rand(64))
      (input + growth.b)
    end
  end

  module Fuzzer
    CRASH_SIGNALS = [
      Signal.list["SEGV"], Signal.list["ABRT"], Signal.list["ILL"]
    ].freeze

    module_function

    def run(binary, seed: "AAAA", inputs: 50, max_len: 256, mutator: :ruby, rng: Random.new)
      # The CTF bread-and-butter first: a deterministic length sweep.
      # Crashes here reveal the OFFSET (the pattern bytes in the faulting
      # address are readable in the triage report).
      sweep = (8..max_len).step(8).map { |len| (seed * (len / seed.length + 1))[0, len] }
      random = case mutator
      when :ruby then RubyMutator.mutate(seed, inputs, rng, max_len: max_len)
      when :radamsa then radamsa_mutations(seed, inputs)
      else raise ArgumentError, "unknown mutator #{mutator.inspect}"
      end

      (sweep + random).filter_map do |input|
        _out, _err, status = Open3.capture3(binary, stdin_data: input)
        {input: input} if status.signaled? && CRASH_SIGNALS.include?(status.termsig)
      end
    end

    def radamsa_mutations(seed, count)
      return Array.new(count) { seed } unless system("sh", "-c", "command -v radamsa >/dev/null 2>&1")

      (0...count).map do
        out, _err, status = Open3.capture3("sh", "-c", "printf '%s' \"$1\" | radamsa", "sh", "-", seed)
        (status.success? && !out.empty?) ? out : seed
      end
    end
  end

  # Crash triage: WHAT happened, in facts the decision layer consumes.
  # Backends are uniform: run(binary, input) -> {signal, registers,
  # fault_addr, control}. Default gdb (batch); rizin/r2 and lldb cover
  # the other toolchains. metasm stays on the static side.
  class TriageError < StandardError; end

  module Triage
    module_function

    def resolve_backend(override: nil)
      candidates = [override, :gdb, :rizin, :lldb].compact
      candidates.find do |b|
        bin = {gdb: "gdb", rizin: "rizin", r2: "radare2", lldb: "lldb"}[b]
        bin && system("sh", "-c", "command -v '#{bin}' >/dev/null 2>&1")
      end
    end

    def run(binary, input, backend: nil)
      resolved = resolve_backend(override: backend)
      raise TriageError, "no triage backend found (gdb, rizin or lldb required)" unless resolved

      send(:"#{resolved}_triage", binary, input)
    end

    # The msf-style pattern: unique 3-grams (aA0aA1...), so ANY 3+ byte
    # subsequence pins its exact offset. The crash address read under the
    # debugger is found back in the pattern - that IS the offset to the
    # return address, computed instead of guessed.
    def cyclic(length)
      out = +""
      until out.size >= length
        ("a".."z").each do |a|
          ("A".."Z").each do |b|
            ("0".."9").each do |c|
              out << a + b + c
              return out[0, length] if out.size >= length
            end
          end
        end
      end
      out[0, length]
    end

    # The offset of `bytes` inside the pattern: try the full register
    # width first, then the 32-bit truncation (the classic case where
    # only four pattern bytes survive in the saved return slot).
    def cyclic_offset(pattern, bytes)
      [8, 4].each do |width|
        next if bytes.bytesize < width

        found = pattern.index(bytes[0, width])
        return found if found
      end
      nil
    end

    # Two steps, like a human would: find the crash LENGTH with the
    # deterministic sweep, then send a cyclic pattern of exactly that
    # length so the crash lands on the corrupted return (an oversized
    # pattern would fault on the stack write itself, never at the ret).
    # The crash address read under the debugger is found back in the
    # pattern - that IS the offset to the return address, computed
    # instead of guessed. Returns nil when the binary does not crash or
    # the pointer is not ours.
    def offset(binary, backend: nil)
      sweep = Fuzzer.run(binary, inputs: 40, max_len: 1024)
      crash_len = sweep.first&.dig(:input)&.bytesize
      return nil unless crash_len

      # The sweep length is the MINIMAL overflow; the pattern needs
      # enough tail to fill the whole saved-return slot with pattern
      # bytes (8 on x64) while staying far from the write-fault zone.
      pattern = cyclic(crash_len + 64)
      report = run(binary, pattern, backend: backend)
      return nil unless report[:signal] == "SIGSEGV"

      # rip first (the clean case); then the saved-frame-pointer slot:
      # a leave;ret epilogue crashes in leave when rbp is smashed, and
      # the return slot sits exactly one register-width above it.
      regs = report[:registers]
      [["rip", 0], ["eip", 0], ["rbp", 8], ["ebp", 8]].each do |reg, shift|
        addr = regs[reg]
        next unless addr.is_a?(String) && addr.start_with?("0x")

        off = cyclic_offset(pattern, [addr[2..].to_i(16)].pack("Q<"))
        return off + shift if off
      end
      nil
    end

    def facts(report)
      return "" unless report[:signal] == "SIGSEGV"

      facts = ["vuln(\"sof\").\n"]
      if report[:control]
        facts << "return_addr_filtered(\"false\").\n"
      end
      facts.join
    end

    def gdb_triage(binary, input)
      input_file = File.join(Dir.tmpdir, "augure_fuzz_input_#{Process.pid}")
      File.binwrite(input_file, input)
      # DEBUGINFOD_URLS empty: gdb's debuginfo auto-download queries the
      # network and turns every batch run into a minutes-long stall (the
      # CI triage went 180s per example on it).
      out, _err, _status = Open3.capture3(
        {"DEBUGINFOD_URLS" => ""}, "gdb", "-batch",
        "-ex", "run < #{input_file}", "-ex", "info registers",
        "-ex", "x/i $pc", binary
      )
      parse_gdb(out)
    ensure
      File.delete(input_file) if input_file && File.exist?(input_file)
    end

    def parse_gdb(output)
      signal = output[/Program received signal (SIG\w+)/, 1]
      registers = {}
      output.each_line do |line|
        if (m = line.match(/\A(\w+)\s+(0x[0-9a-f]+|\d+)\s/))
          registers[m[1]] = m[2]
        end
      end
      # The faulting address: the instruction pointer when control was
      # hijacked, else the faulting line's address.
      fault_addr = registers["rip"] || registers["eip"] || output[/\A(0x[0-9a-f]+)/, 1]
      control = detect_control(registers, output)
      {signal: signal, registers: registers, fault_addr: fault_addr, control: control}
    end

    # Input-pattern control: the faulting address is made of pattern
    # bytes - the return address IS under input control.
    def detect_control(registers, _output)
      %w[rip eip].each do |reg|
        addr = registers[reg]
        next unless addr.is_a?(String) && addr.start_with?("0x")

        bytes = [addr[2..].to_i(16)].pack("Q<").delete("\x00A")
        return reg.to_sym if addr.include?("4141") || bytes.empty?
      end
      :none
    end

    def rizin_triage(binary, input)
      input_file = File.join(Dir.tmpdir, "augure_fuzz_input_#{Process.pid}")
      File.binwrite(input_file, input)
      out, _err, _status = Open3.capture3(
        "rizin", "-d", "-q", "-c", "dc; drp; dk 9", binary, "-", "<", input_file
      )
      parse_rizin(out)
    ensure
      File.delete(input_file) if input_file && File.exist?(input_file)
    end

    def parse_rizin(output)
      signal = output[/signal (\d+|SIG\w+)/, 1] ? "SIGSEGV" : nil
      signal ||= "SIGSEGV" if /Segmentation fault/.match?(output)
      registers = {}
      output.each_line do |line|
        if (m = line.match(/\A(\w+)\s+=\s+(0x[0-9a-f]+)/))
          registers[m[1]] = m[2]
        end
      end
      {signal: signal, registers: registers, fault_addr: registers["rip"] || registers["eip"],
       control: :none}
    end

    def lldb_triage(binary, input)
      input_file = File.join(Dir.tmpdir, "augure_fuzz_input_#{Process.pid}")
      File.binwrite(input_file, input)
      out, _err, _status = Open3.capture3(
        "lldb", "--batch", "-o", "run < #{input_file}", "-o", "register read",
        "-o", "bt", binary
      )
      parse_lldb(out)
    ensure
      File.delete(input_file) if input_file && File.exist?(input_file)
    end

    def parse_lldb(output)
      signal = output[/received signal (SIG\w+)/, 1]
      registers = {}
      output.each_line do |line|
        if (m = line.match(/\A\s*(\w+) = (0x[0-9a-f]+)/))
          registers[m[1]] = m[2]
        end
      end
      {signal: signal, registers: registers, fault_addr: registers["rip"] || registers["eip"],
       control: :none}
    end
  end
end
