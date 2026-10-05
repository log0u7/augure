# frozen_string_literal: true

require "augure-profiler"
require_relative "support/binary_builder"

RSpec.describe AugureProfiler::Profiler do
  let(:dir) { BinaryBuilder.build }
  let(:vuln) { File.join(dir, "vuln_nx_off_nopie") }
  let(:hardened) { File.join(dir, "hardened_full_relro") }

  describe "checksec facts" do
    it "reads NX off, no PIE, no canary, partial RELRO on the vulnerable build" do
      facts = described_class.new(vuln).facts
      expect(facts.rel("nx")).to eq([["false"]])
      expect(facts.rel("pie")).to eq([["false"]])
      expect(facts.rel("canary")).to eq([["false"]])
      expect(facts.rel("relro")).to eq([["partial"]])
    end

    it "reads NX on, PIE on, canary on, full RELRO on the hardened build" do
      facts = described_class.new(hardened).facts
      expect(facts.rel("nx")).to eq([["true"]])
      expect(facts.rel("pie")).to eq([["true"]])
      expect(facts.rel("canary")).to eq([["true"]])
      expect(facts.rel("relro")).to eq([["full"]])
    end
  end

  describe "imports and unsafe hints" do
    it "emits plt facts for imports and vuln_hint for unsafe functions" do
      facts = described_class.new(vuln).facts
      expect(facts.rel("plt")).to include(["gets"])
      expect(facts.rel("vuln_hint")).to include(["unsafe_func:gets"])
    end

    it "emits plt_addr and got_addr for the JMP_SLOT imports (the builder needs addresses)" do
      # plt(name) is the rule vocabulary; plt_addr(name, addr) and
      # got_addr(name, addr) carry the addresses a ROP chain resolves
      facts = described_class.new(vuln).facts
      addrs = facts.rel("plt_addr")
      expect(addrs).not_to be_empty
      addrs.each { |(name, addr)| expect(addr).to be_an(Integer) }
      gots = facts.rel("got_addr")
      expect(gots.map(&:first)).to eq(addrs.map(&:first)) # one entry per JMP_SLOT import, same order
      gots.each { |(_, addr)| expect(addr).to be > 0 }
    end

    it "does NOT flag printf as a vuln hint (a constant format is not a vuln)" do
      # every binary imports printf; the hint would derive vuln(fmtstr)
      # everywhere - sprintf stays flagged (unbounded by design), the
      # controlled-format knowledge is the operator's suggest flow
      dir = Dir.mktmpdir
      src = File.join(dir, "printf_user.c")
      File.write(src, "int main(void) { printf(\"constant\\n\"); return 0; }")
      bin = BinaryBuilder.gcc(dir, src, "printf_user")
      facts = described_class.new(bin).facts
      hints = facts.rel("vuln_hint") || []
      expect(hints).not_to include(["unsafe_func:printf"])
    end

    it "does NOT emit plt for a local function named like an import" do
      # the ret2plt trap: plt("system") on a local function makes the
      # decision layer believe a PLT stub exists that does not
      local = BinaryBuilder.local_system
      facts = described_class.new(local).facts
      names = facts.rel("plt").map(&:first)
      expect(names).not_to include("system")
      expect(names).to include("__libc_start_main") # a real import stays
    end

    it "does not emit plt for internal non-function symbols" do
      # main/_start/_DYNAMIC/etc. are not imports even when
      # identifier-shaped
      facts = described_class.new(vuln).facts
      names = facts.rel("plt").map(&:first)
      expect(names).not_to include("main", "_start", "_DYNAMIC", "data_start")
      expect(names).to all(match(/\A[a-zA-Z_][a-zA-Z0-9_]*\z/))
    end
  end

  describe "gadget enumeration" do
    let(:gadget_bin) { BinaryBuilder.gadget_binary(dir) }

    it "classifies documented semantic gadget types" do
      facts = described_class.new(gadget_bin).facts
      types = facts.rel("gadget").map(&:first)
      expect(types).to include("pop_rdi_ret")
      expect(types).to include("ret_align")
      expect(types).to include("syscall_ret")
      expect(types).to include("xchg_rsp_rax")
      expect(types).to include("mov_deref_write")
      expect(types).to include("jmp_rsp")
    end

    it "emits gadget facts with integer addresses" do
      facts = described_class.new(gadget_bin).facts
      facts.rel("gadget").each do |tuple|
        expect(tuple[1]).to be_a(Integer)
        expect(tuple[1]).to be > 0
      end
    end
  end

  describe "the facts contract" do
    it "produces facts the augure engine parses without error" do
      facts = described_class.new(vuln).facts
      roundtrip = Augure::Facts.parse(facts.to_s)
      expect(roundtrip.rel("nx")).to eq(facts.rel("nx"))
    end

    it "feeds a full decision end to end" do
      facts = described_class.new(vuln).facts
      result = Augure::Pipeline.analyze(facts: facts, seed: 42)
      expect(result[:ranking].first).to eq("shellcode")
    end
  end
end
