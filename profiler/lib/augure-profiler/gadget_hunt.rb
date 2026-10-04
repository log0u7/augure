# frozen_string_literal: true

require "metasm"
require_relative "static_offset"

module AugureProfiler
  # The general gadget hunter: the byte patterns catch the classics;
  # this walks EVERY offset of the executable sections, decodes the
  # chain that ends on a ret, and classifies it semantically. The
  # multi-instruction gadgets (pop rsi; pop r15; ret) the patterns
  # never see come out of here.
  module GadgetHunt
    MAX_CHAIN = 8
    # the instructions that end a hunt-able chain
    TERMINAL = %w[ret].freeze
    # the semantics that kill control (the chain dies there)
    KILLERS = %w[call jmp lret hlt iret syscall int leave loop].freeze

    module_function

    # Returns [{type:, addr:}] - the facts-ready tuples.
    def hunt(path)
      elf = Metasm::ELF.decode_file(path)
      arch = (elf.header.e_class.to_s == "64") ? :x64 : :x86
      cpu = (arch == :x64) ? Metasm::X64.new : Metasm::Ia32.new
      gadgets = []
      elf.sections.select { |s| s.flags.map(&:to_s).include?("EXECINSTR") && s.size.to_i > 0 }
        .each do |sec|
        data = StaticOffset.section_data(path, sec)
        base = sec.addr.to_i
        (0...data.bytesize).each do |i|
          chain = decode_chain(cpu, data, i, base)
          next unless chain

          type = classify(chain)
          next unless type

          gadgets << {type: type, addr: base + i}
        end
      end
      gadgets
    end

    # decode up to MAX_CHAIN instructions starting at offset i; the
    # chain must END on a terminal (ret) with no killer inside. Returns
    # the instruction STRINGS or nil.
    def decode_chain(cpu, data, i, _base)
      instrs = []
      off = i
      limit = data.bytesize
      MAX_CHAIN.times do
        return nil if off >= limit

        di = decode_at(cpu, data, off)
        return nil unless di

        text = di.instruction.to_s
        op = di.instruction.opname
        return nil if KILLERS.include?(op)

        break if TERMINAL.include?(op)

        instrs << text
        off += di.bin_length.to_i
        return nil if instrs.size >= MAX_CHAIN
      end
      return nil if instrs.empty?

      instrs + ["ret"]
    end

    # decode one instruction at data offset off - metasm's one-shot
    # decode_instruction on the raw bytes
    def decode_at(cpu, data, off)
      di = cpu.decode_instruction(Metasm::EncodedData.new(data[off..]), 0)
      di&.instruction ? di : nil
    rescue Metasm::DecodeError, Metasm::ParseError, StandardError
      nil
    end

    def classify(instrs)
      tail = instrs.last
      return nil unless tail == "ret"

      pops = instrs[0...-1].select { |i| i.start_with?("pop ") }
      if instrs.length == pops.length + 1 && pops.any?
        regs = pops.map { |i| i.delete_prefix("pop ") }
        return "pop_#{regs.join("_")}_ret"
      end
      return "syscall_ret" if instrs.length == 2 && instrs.first.start_with?("syscall")
      return "int80_ret" if instrs.length == 2 && instrs.first.start_with?("int 0x80")
      return "xchg_rsp_rax" if instrs.length == 2 && instrs.first =~ /xchg .*rsp.*|xchg .*esp.*/

      if instrs.length == 2 && instrs.first.start_with?("mov ") && instrs.first.include?("[") &&
          instrs.first.include?("]")
        return "mov_deref_write"
      end
      nil
    end
  end
end
