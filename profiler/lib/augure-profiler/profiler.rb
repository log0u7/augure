# frozen_string_literal: true

require "metasm"
require "augure"

module AugureProfiler
  # Binary profiler: ELF in, augure facts out. The profiler speaks the fact
  # schema and nothing else - augure decides, it never sees a binary.
  #
  # checksec comes from metasm ELF structures (pure Ruby, no subprocess);
  # gadget enumeration slides semantic byte patterns over executable
  # sections, named exactly like the frozen corpus vocabulary.
  class Profiler
    # Semantic names for ret-terminated gadget byte patterns, documented
    # and ordered longest-first so the longest match wins.
    GADGET_PATTERNS = [
      ["mov_deref_write", "48 89 38 c3"],   # mov [rax], rdi ; ret
      ["mov_deref_write", "48 89 30 c3"],   # mov [rax], rsi ; ret
      ["mov_deref_write", "48 89 10 c3"],   # mov [rax], rdx ; ret
      ["mov_deref_write", "4d 89 3e c3"],   # mov [r14], r15 ; ret (ROP Emporium write4)
      ["xchg_rsp_rax", "48 94 c3"],         # xchg rsp, rax ; ret
      ["syscall_ret", "0f 05 c3"],          # syscall ; ret
      ["int80_ret", "cd 80 c3"],            # int 0x80 ; ret
      ["pop_rdi_ret", "5f c3"],             # pop rdi ; ret
      ["pop_rsi_ret", "5e c3"],             # pop rsi ; ret
      ["pop_rdx_ret", "5a c3"],             # pop rdx ; ret
      ["pop_rax_ret", "58 c3"],             # pop rax ; ret
      ["JMP_STACK", "ff e4"],               # jmp esp/rsp - renamed per arch
      ["ret_align", "c3"]                   # ret
    ].freeze

    # printf is NOT on the list: a constant format is not a vuln, and
    # the hint would derive vuln(fmtstr) for every binary that prints -
    # sprintf stays (unbounded by design).
    UNSAFE_SYMBOLS = %w[gets strcpy strcat sprintf scanf].freeze

    ET_DYN = "DYN"

    def initialize(path)
      @path = path
      @elf = Metasm::ELF.decode_file(path)
    end

    def facts
      facts = Augure::Facts.new
      emit_checksec(facts)
      emit_symbols(facts)
      emit_gadgets(facts)
      facts
    end

    private

    def emit_checksec(facts)
      facts.add("nx", exec_stack? ? "false" : "true")
      facts.add("pie", (@elf.header.type.to_s == ET_DYN) ? "true" : "false")
      facts.add("relro", relro_state)
    end

    def exec_stack?
      stack = @elf.segments.find { |s| s.type.to_s == "GNU_STACK" }
      stack&.flags&.map(&:to_s)&.include?("X")
    end

    def relro_state
      relro = @elf.segments.any? { |s| s.type.to_s == "GNU_RELRO" }
      return "none" unless relro

      tags = @elf.instance_variable_get(:@tag) || {}
      flags = (tags["FLAGS"] || []) + (tags["FLAGS_1"] || [])
      (flags.any? { |f| f.to_s =~ /BIND_NOW|NOW/ }) ? "full" : "partial"
    end

    def emit_symbols(facts)
      names = @elf.symbols.map(&:name).compact.uniq
      # plt facts describe REAL dynamic imports (shndx == UNDEF, FUNC
      # type) - not any identifier-shaped symbol: a local function
      # named `system` must not make the decision layer believe a PLT
      # stub exists.
      @elf.symbols.each do |sym|
        facts.add("plt", sym.name) if plt_symbol?(sym)
      end
      emit_plt_addresses(facts)
      names.each do |n|
        facts.add("vuln_hint", "unsafe_func:#{n}") if UNSAFE_SYMBOLS.include?(n)
      end
      # CTF heuristic: a local win/flag function = a callable target
      # (the ret2func family's target_function fact). The winning
      # symbol keeps its name AND its address - the payload builder
      # needs the address, not just the existence.
      @elf.symbols.each do |sym|
        next unless sym.name.to_s.match?(/\Awin\z|win\z|flag\z/)

        facts.add("target_function", "true")
        facts.add("win_symbol", sym.name, sym.value.to_i)
      end
      if names.include?("__stack_chk_fail")
        facts.add("canary", "true")
      else
        facts.add("canary", "false")
      end
    end

    # The addresses a ROP chain resolves against: the JMP_SLOT
    # relocations carry the GOT entry (r_offset) and the PLT stub is
    # computable from the section layout (.plt.sec: 16*i; .plt: 16*(i+1)).
    def emit_plt_addresses(facts)
      plt_sec = @elf.sections.find { |s| s.name.to_s == ".plt.sec" }
      plt = @elf.sections.find { |s| s.name.to_s == ".plt" }
      jmp_slots = @elf.relocations.select { |r| r.type.to_s.include?("JMP_SLOT") }
      jmp_slots.each_with_index do |r, i|
        name = r.symbol&.name
        next unless name.is_a?(String) && !name.empty?

        stub = if plt_sec
          plt_sec.addr.to_i + 16 * i
        else
          plt && (plt.addr.to_i + 16 * (i + 1))
        end
        facts.add("got_addr", name, r.offset.to_i) if r.offset
        facts.add("plt_addr", name, stub) if stub
      end
    end

    def arch_index
      (@elf.header.e_class.to_s == "64") ? 0 : 1
    end

    def plt_symbol?(sym)
      sym.name.to_s =~ /\A[a-zA-Z_][a-zA-Z0-9_]*\z/ &&
        sym.shndx.to_s == "UNDEF" && sym.type.to_s == "FUNC"
    end

    def emit_gadgets(facts)
      executable_sections.each do |section|
        bytes = section_bytes(section)
        next if bytes.nil? || bytes.empty?

        stack_jump = %w[jmp_rsp jmp_esp][arch_index]
        scan_gadgets(bytes, section.addr.to_i).each do |(type, addr)|
          name = type
          name = stack_jump if type == "JMP_STACK"
          facts.add("gadget", name, addr)
        end
      end
      emit_csu_gadgets(facts)
    end

    def executable_sections
      @elf.sections.select { |s| s.flags.map(&:to_s).include?("EXECINSTR") }
    end

    # metasm exposes section metadata but not raw bytes here; read straight
    # from the file at the section offset.
    def section_bytes(section)
      File.open(@path) do |f|
        f.seek(section.offset.to_i)
        f.read(section.size.to_i)
      end&.bytes
    rescue
      nil
    end

    # The patterns precompiled ONCE to byte arrays: scanning compares
    # integers (String#index skip), not hex-string slices per position
    # (the old hex.map + split-per-position was ~100x slower).
    # The patterns precompiled ONCE to binary strings: the scan runs
    # String#index (memmem in C) per pattern, not a hex-slice compare
    # per byte position (the original was ~100x slower; an Array-slice
    # version was 2x slower still).
    GADGET_BIN = GADGET_PATTERNS.map do |(type, pattern)|
      [type, pattern.split(" ").map { |h| h.to_i(16) }.pack("C*")]
    end.freeze

    def scan_gadgets(bytes, base_addr)
      data = bytes.is_a?(String) ? bytes : bytes.pack("C*")
      data = data.b
      hits = []
      GADGET_BIN.each_with_index do |(type, pat), order|
        off = 0
        while (off = data.index(pat, off))
          hits << [order, type, base_addr + off]
          off += pat.size
        end
      end
      # position first, then the pattern-table order (the original
      # first-match-wins semantics preserved byte for byte)
      hits.sort_by! { |(order, _type, addr)| [addr, order] }
      hits.map { |(_order, type, addr)| [type, addr] }
    end

    # Static binaries expose the __libc_csu_init universal gadgets under
    # well-known symbols; their presence IS the gadget fact.
    def emit_csu_gadgets(facts)
      names = @elf.symbols.map(&:name).compact
      return unless names.include?("__libc_csu_init")

      sym = @elf.symbols.find { |s| s.name == "__libc_csu_init" }
      facts.add("gadget", "csu_popper", sym.value.to_i)
      facts.add("gadget", "csu_mov", sym.value.to_i + 0x40)
    end
  end
end
