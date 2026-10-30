# frozen_string_literal: true

require "metasm"

module AugureProfiler
  # The gdb-free offset: read it straight off the frame. Decode the ELF,
  # resolve the unsafe imports' PLT stubs (the .rela.plt order), find the
  # call site, and read the buffer's rbp displacement in the argument
  # setup: offset = displacement + saved-rbp + return slot. The debugger
  # stays as the verifier, not the measurer.
  module StaticOffset
    # The unbounded family: no length argument exists, the copy runs to
    # the NUL (or the newline). Any call site feeding it a stack buffer
    # is the overflow, no further question asked.
    UNSAFE_CALLS = %w[strcpy gets scanf sprintf readline strcat].freeze
    # The sized family: the length rides in an argument (rdx on x64).
    # When that argument is an immediate at most as large as the room
    # between the buffer and the return slot, the copy cannot reach it:
    # a bounded call, not the overflow - the scan moves on. A register
    # (the read's count, the ret2plt memcpy) is unbounded by definition.
    BOUNDED_CALLS = %w[read fgets fread memcpy memmove strncpy].freeze
    # The variadic format users: the format argument is the attacker's
    # bytes only when it comes from a stack buffer.
    PRINTF_LIKE = %w[printf fprintf].freeze

    module_function

    # metasm leaves section.encoded nil on decode: the raw bytes come
    # from the file at the section's offset (same as the profiler).
    def self.section_data(path, sec)
      File.open(path) do |f|
        f.seek(sec.offset.to_i)
        f.read(sec.size.to_i)
      end
    end

    # Returns {offset:, sink:, function:} or nil when no unsafe call site
    # carries a readable rbp-frame buffer.
    def offset(path, calls: UNSAFE_CALLS + BOUNDED_CALLS)
      elf = Metasm::ELF.decode_file(path)
      arch = (elf.header.e_class.to_s == "64") ? :x64 : :x86
      @path = path
      stubs = plt_stubs(elf, arch)
      unsafe = stubs.slice(*calls)
      return nil if unsafe.empty?

      @unsafe_addrs = unsafe.invert

      text = elf.sections.find { |s| s.name == ".text" }
      data = section_data(@path, text)
      bytes = data.bytes
      # The CHEAP scan first: a linear e8 rel32 walk nets every call to
      # an unsafe stub - the full .text disassembly (minutes on a 1MB
      # text) is only needed if this finds nothing. Sites without an
      # rbp-frame buffer (a global, a pointer arg) no longer stop the
      # scan: a later site may carry the overflow.
      call_site = nil
      sink = nil
      bytes.each_index do |i|
        next unless bytes[i] == 0xe8

        target = text.addr + i + 5 + bytes[(i + 1)..(i + 4)].pack("C*").unpack1("l<")
        next unless (name = @unsafe_addrs[target])

        site = text.addr + i
        frame = frame_bytes(data, site - text.addr, arch)
        next if frame.nil? || !frame[:offset]&.positive?

        next if BOUNDED_CALLS.include?(name) &&
          size_imm_cannot_reach?(bytes, site - text.addr, frame[:offset], arch, name)

        call_site = site
        sink = name
        break
      end
      unless call_site
        # LAST RESORT: the flow disassembly of the whole .text (minutes
        # on a 1MB text - the e8 scan above almost always wins).
        cpu = (arch == :x64) ? Metasm::X64.new : Metasm::Ia32.new
        sc = Metasm::Shellcode.new(cpu)
        sc.base_addr = text.addr
        sc.encoded = Metasm::EncodedData.new(data)
        ds = sc.disassemble(text.addr)
        elf.symbols.select do |sym|
          sym.type.to_s == "FUNC" && sym.value.to_i >= text.addr && sym.value.to_i < text.addr + text.size.to_i
        end
          .each { |sym| ds.disassemble(sym.value) }
        instrs = ds.decoded.to_a.sort_by { |a, _| a }.map { |a, di| [a, di.instruction] }
        call_idx = instrs.index do |_a, instr|
          next false unless instr.opname == "call"

          arg = instr.args.first
          arg.respond_to?(:expression) ? @unsafe_addrs.key?(arg.expression.reduce.to_i) : false
        end
        call_site = call_idx && instrs.dig(call_idx, 0)
        if call_site
          arg = instrs.dig(call_idx, 1)&.args&.first
          sink = arg&.respond_to?(:expression) ? @unsafe_addrs[arg.expression.reduce.to_i] : nil
        end
      end
      result = if call_site.is_a?(Integer) # nil or Integer: nil.is_a? is false
        frame_bytes(data, call_site - text.addr, arch)
      elsif call_site
        frame_disp(instrs, call_idx, arch)
      end
      result&.tap do |r|
        r[:sink] ||= sink
        site = call_site
        r[:function] = enclosing_function(elf, site.to_i)
      end
    rescue Metasm::ParseError, Metasm::InvalidExeFormat
      nil
    end

    # Byte-pattern net: lea reg, [rbp-disp8] anywhere in the window
    # before the unsafe call. x64: [REX.W] 8d modrm(mod=01,rm=101) disp8;
    # x86: 8d modrm(mod=01,rm=101) disp8 (rbp/ebp addressed frames only).
    def frame_bytes(data, call_off, arch)
      width = (arch == :x64) ? 8 : 4
      saved = width
      rex_w = (arch == :x64) ? [0x48, 0x49, 0x4c, 0x4d] : nil
      start = [call_off - 64, 2].max
      (call_off - 2).downto(start) do |j|
        modrm = data.getbyte(j)
        next unless (modrm & 0xC7) == 0x45
        next unless data.getbyte(j - 1) == 0x8d
        next unless (arch == :x64) ? rex_w.include?(data.getbyte(j - 2)) : true

        disp = data.getbyte(j + 1)
        disp -= 256 if disp > 127
        return {offset: saved - disp, sink: nil}
      end
      nil
    end

    # The sized family's length argument rides rdx (x64): an immediate
    # at most as large as the room between the buffer and the return
    # slot means the copy cannot reach it. x86 passes the length on the
    # stack, no immediate to read: treated as unbounded (the
    # conservative direction: a false vuln beats a missed one).
    def size_imm_cannot_reach?(bytes, call_off, room, arch, sink)
      return false unless arch == :x64

      # the length argument's register: rdx for the memcpy family, rsi
      # for fgets (buf, size, stream)
      opcodes = (sink == "fgets") ?
        [[0xbe], [0x48, 0xc7, 0xc6], [0x49, 0xc7, 0xc6]] : # mov esi/rsi, imm32
        [[0xba], [0x48, 0xc7, 0xc2], [0x49, 0xc7, 0xc2]]   # mov edx/rdx, imm32

      start = [call_off - 16, 0].max
      (start..(call_off - 5)).each do |j|
        opcodes.each do |ops|
          if ops.size == 1
            return true if bytes[j] == ops[0] && (imm = imm32(bytes, j + 1)) && imm <= room
          elsif j >= ops.size - 1
            opcode_ok = (1...(ops.size)).all? { |k| bytes[j - k] == ops[ops.size - 1 - k] }
            return true if opcode_ok && bytes[j] == ops.last && (imm = imm32(bytes, j + 1)) && imm <= room
          end
        end
      end
      false
    end

    def imm32(bytes, off)
      return nil if off.negative? || off + 4 > bytes.size

      bytes[off, 4].pack("C*").unpack1("L<")
    end

    # The printf-family sites whose format argument is a STACK buffer:
    # lea reg,[rbp-disp] feeding rdi (directly, 48 8d 7d d8, or through
    # a register move, 48 8d 45 d8 then 48 89 c7) means the format is
    # the attacker's bytes - the fmtstr class. A .rodata format rides
    # an immediate (mov edi, imm32): not a vuln. x86 passes args on the
    # stack, no lea-into-rdi idiom to read: nil (an honest miss).
    def stack_format_sink(path)
      elf = Metasm::ELF.decode_file(path)
      arch = (elf.header.e_class.to_s == "64") ? :x64 : :x86
      return nil unless arch == :x64

      @path = path # plt_stubs reads the section bytes through @path

      stubs = plt_stubs(elf, arch)
      like = stubs.slice(*PRINTF_LIKE)
      return nil if like.empty?

      like_addrs = like.invert
      text = elf.sections.find { |s| s.name == ".text" }
      data = section_data(path, text)
      bytes = data.bytes
      bytes.each_index do |i|
        next unless bytes[i] == 0xe8

        target = text.addr + i + 5 + bytes[(i + 1)..(i + 4)].pack("C*").unpack1("l<")
        next unless like_addrs[target]

        return like_addrs[target] if stack_format_rdi?(bytes, i)
      end
      nil
    rescue Metasm::ParseError, Metasm::InvalidExeFormat
      nil
    end

    # a mini-modrm decode of the lea feeding the format argument: REX.W
    # (48) + 8d + modrm(mod=01|10, rm=101=rbp) = lea reg,[rbp-disp8|32].
    # reg=rdi (111) is the direct form; reg=rax (000) needs the
    # immediate mov rdi, rax (48 89 c7) right after the lea. Only 0x48
    # qualifies as REX: REX.B would turn rbp into r13.
    def stack_format_rdi?(bytes, call_off)
      start = [call_off - 24, 0].max
      (start...(call_off - 3)).each do |j|
        next unless bytes[j] == 0x48
        next unless bytes[j + 1] == 0x8d

        modrm = bytes[j + 2]
        mod = modrm >> 6
        next unless mod == 0b01 || mod == 0b10
        next unless (modrm & 7) == 0b101

        reg = (modrm >> 3) & 7
        len = (mod == 0b01) ? 4 : 7
        return true if reg == 0b111
        next unless reg == 0b000

        return true if bytes[j + len, 3] == [0x48, 0x89, 0xc7]
      end
      false
    end

    # The buffer displacement in the argument setup, then the frame math:
    # on x64: [rbp-N] -> saved rbp at N..N+8, return at N+8..N+16.
    def frame_disp(instrs, call_idx, arch)
      saved = (arch == :x64) ? 8 : 4
      base = (arch == :x64) ? "rbp" : "ebp"
      instrs[[call_idx - 8, 0].max...call_idx].reverse_each do |di|
        s = di.instruction.to_s
        next unless di.opname == "lea" && s =~ /\[#{base}(-0x[0-9a-f]+)\]/i

        disp = Regexp.last_match(1).to_i(16)
        return {offset: saved - disp,
                sink: @unsafe_addrs[instrs[call_idx].instruction.args.first.expression.reduce.to_i]}
      end
      nil
    end

    def enclosing_function(elf, addr)
      func = elf.symbols.select { |s| s.type.to_s == "FUNC" && s.value.to_i > 0 }
        .find { |s| addr.to_i >= s.value.to_i && addr.to_i < s.value.to_i + s.size.to_i }
      func&.name.to_s
    end

    # .rela.plt order. CFI toolchains put the call targets in .plt.sec
    # (16 * i, same order); the classic .plt has PLT0 first (16 * (i + 1)).
    # The symbol index indexes .dynsym.
    def plt_stubs(elf, _arch)
      pltsec = elf.sections.find { |s| s.name == ".plt.sec" }
      plt = pltsec || elf.sections.find { |s| s.name == ".plt" }
      rela = elf.sections.find { |s| s.name == ".rela.plt" }
      dynsym = elf.sections.find { |s| s.name == ".dynsym" }
      dynstr = elf.sections.find { |s| s.name == ".dynstr" }
      return {} unless plt && rela && dynsym && dynstr

      sym_data = section_data(@path, dynsym)
      str_data = section_data(@path, dynstr)
      name_at = lambda do |idx|
        off = sym_data[idx * 24, 4].unpack1("V")
        str_data[off..].unpack1("Z*")
      end

      entries = section_data(@path, rela)
      count = entries.size / 24
      stubs = {}
      count.times do |i|
        r_info = entries[i * 24 + 8, 8].unpack1("Q<")
        name = name_at.call(r_info >> 32)
        stubs[name] = (plt.name == ".plt.sec") ? plt.addr + 16 * i : plt.addr + 16 * (i + 1)
      end
      stubs
    end

    # Gadget honesty: a fact claims "at this address there is a ret" -
    # re-decode the bytes and confirm the claim before anything consumes
    # it. A lying gadget (wrong address, mid-instruction c3) is refused.
    # Returns true when the decoded chain matches the type's semantics.
    def self.verify_gadget(path, type, addr)
      elf = Metasm::ELF.decode_file(path)
      sec = elf.sections.find do |s|
        s.flags.map(&:to_s).include?("EXECINSTR") &&
          addr.to_i >= s.addr.to_i && addr.to_i < s.addr.to_i + s.size.to_i
      end
      return false unless sec

      arch = (elf.header.e_class.to_s == "64") ? :x64 : :x86
      cpu = (arch == :x64) ? Metasm::X64.new : Metasm::Ia32.new
      data = section_data(path, sec)
      sc = Metasm::Shellcode.new(cpu)
      sc.base_addr = sec.addr.to_i
      sc.encoded = Metasm::EncodedData.new(data)
      ds = sc.disassemble(addr.to_i)
      di = ds.di_at(addr.to_i)
      return false unless di

      expected = expected_chain(type, arch)
      return false if expected.empty?

      cur = addr.to_i
      expected.each do |want|
        di = ds.di_at(cur) || (ds.disassemble(cur) && ds.di_at(cur))
        return false unless di

        instr = di.instruction.to_s
        case want
        when /\Apop (.+)\z/
          return false unless di.instruction.opname == "pop" && di.instruction.args.first.to_s == Regexp.last_match(1)
        when /\Ajmp (.+)\z/
          return false unless di.instruction.opname == "jmp" && instr.include?(Regexp.last_match(1))
        else
          return false unless instr == want || instr.start_with?(want)
        end
        cur += di.bin_length.to_i
      end
      true
    rescue Metasm::ParseError, Metasm::InvalidExeFormat
      false
    end

    def self.expected_chain(type, arch)
      sp = (arch == :x64) ? "rsp" : "esp"
      case type
      when "ret_align" then ["ret"]
      when "jmp_rsp" then ["jmp #{sp}"]
      when "jmp_esp" then ["jmp #{sp}"]
      when "syscall_ret" then %w[syscall ret]
      when "int80_ret" then ["int"]
      when /\Apop_.*_ret\z/
        type.delete_prefix("pop_").delete_suffix("_ret").split("_").map { |r| "pop #{r}" } + ["ret"]
      else
        []
      end
    end

    # The crash, identified instead of guessed. The runtime rip cannot be
    # slid back through ASLR, so the identification comes from the STATIC
    # side: the vulnerable function and its sink are facts the frame read
    # already established, and the CONTROL evidence is the pattern the
    # cyclic input planted in the registers (rbp/rip carrying pattern
    # bytes = the saved frame IS ours - the old tool inferred this from
    # 0x41414141 shapes; here the pattern is known, so the proof is exact).
    def self.crash_facts(path, report)
      return {} unless report.is_a?(Hash) && report[:signal] == "SIGSEGV"

      static = offset(path) || {}
      facts = {vuln_function: static[:function], sink: static[:sink]}.compact

      pattern = nil
      if static[:offset]
        sweep = begin
          AugureProfiler::Fuzzer.run(path, inputs: 40, max_len: 1024)
        rescue
          nil
        end
        crash_len = sweep&.first&.dig(:input)&.bytesize
        pattern = Triage.cyclic(crash_len + 64) if crash_len
      end

      controlled = %w[rip rsp rbp rax rbx rcx rdx rdi rsi r8 r9 r10 r11 r12 r13 r14 r15]
        .any? do |reg|
          val = report.dig(:registers, reg)
          next false unless val.is_a?(String) && val.start_with?("0x")

          raw = [val[2..].to_i(16)].pack("Q<")
          # the register carries OUR bytes: a pattern subsequence (truncated
          # to 4 bytes covers the classic ret-slot window) or the A-fill
          raw.include?("AAAA") || (pattern && [8, 4].any? { |w| pattern.include?(raw[0, w]) })
        end
      facts[:crash_site] = controlled ? "ret" : "unknown"
      facts
    end
  end
end
