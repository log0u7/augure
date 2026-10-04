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

    UNSAFE_SYMBOLS = %w[gets strcpy strcat sprintf scanf printf].freeze

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

    def scan_gadgets(bytes, base_addr)
      gadgets = []
      hex = bytes.map { |b| b.to_s(16).rjust(2, "0") }
      i = 0
      while i < hex.size
        hit = GADGET_PATTERNS.find do |(_type, pattern)|
          pattern_hex = pattern.split(" ")
          hex[i, pattern_hex.size] == pattern_hex
        end
        if hit
          gadgets << [hit[0], base_addr + i]
          i += hit[1].split(" ").size
        else
          i += 1
        end
      end
      gadgets
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
