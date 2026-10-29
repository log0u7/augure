# frozen_string_literal: true

require "augure-profiler"
require_relative "support/binary_builder"

RSpec.describe AugureProfiler::Profiler do
  # The csu byte signatures, both known compiler flavors:
  #   newer:  mov rdx,r15 ; mov rsi,r14 ; mov edi,r13d ; call [r12+rbx*8]
  #   classic: mov rdx,r13 ; mov rsi,r14 ; mov edi,r15d ; call [r12+rbx*8]
  let(:nop) { "\x90".b }
  let(:newer_mov) { ["4c89fa4c89f64489ef41ff14dc"].pack("H*") }
  let(:classic_mov) { ["4c89ea4c89f64489ff41ff14dc"].pack("H*") }
  # add rsp,8 ; pop rbx,rbp,r12,r13,r14,r15 ; ret - the popper fact aims
  # at the pop rbx (the chain entry the writeups use)
  let(:popper) { ["4883c408"].pack("H*") + ["5b5d415c415d415e415fc3"].pack("H*") }

  describe ".csu_gadget_addrs" do
    it "locates both gadgets by byte signature in the newer flavor" do
      blob = (nop * 8) + newer_mov + (nop * 4) + popper + (nop * 8)
      base = 0x400640
      addrs = described_class.csu_gadget_addrs(blob, base, blob.bytesize)
      expect(addrs[:mov]).to eq(base + 8)
      expect(addrs[:popper]).to eq(base + 8 + NEWER_MOV.bytesize + 4 + 4)
    end

    it "locates both gadgets in the classic flavor too" do
      blob = (nop * 4) + classic_mov + (nop * 2) + popper
      base = 0x400640
      addrs = described_class.csu_gadget_addrs(blob, base, blob.bytesize)
      expect(addrs[:mov]).to eq(base + 4)
      expect(addrs[:popper]).to eq(base + 4 + CLASSIC_MOV.bytesize + 2 + 4)
    end

    it "reports nothing when the signatures are absent" do
      blob = nop * 64
      addrs = described_class.csu_gadget_addrs(blob, 0x400640, blob.bytesize)
      expect(addrs[:mov]).to be_nil
      expect(addrs[:popper]).to be_nil
    end
  end

  describe "#facts, a binary carrying the callme gadget" do
    it "emits pop_rsi_r15_ret and keeps the overlapping pop_rdi_ret" do
      bin = ProfilerBinaryBuilder.pop_rsi_r15
      facts = described_class.new(bin).facts.to_s
      expect(facts).to match(/gadget\("pop_rsi_r15_ret", \d+\)/)
      expect(facts).to match(/gadget\("pop_rdi_ret", \d+\)/)
    end
  end

  describe "#facts, a binary whose ret2win is an import" do
    it "emits no win_symbol for a symbol that is not defined here" do
      bin = ProfilerBinaryBuilder.importing_win
      facts = described_class.new(bin).facts.to_s
      expect(facts).to match(/plt\("ret2win"\)/)
      expect(facts).not_to match(/win_symbol/)
      expect(facts).not_to match(/target_function/)
    end
  end

  describe "#facts, the real ret2csu challenge binary" do
    path = "/tmp/opencode/csu/ret2csu"

    it "emits the popper at the epilogue, not at the symbol entry" do
      skip "the ropemporium cache is not present" unless File.file?(path)
      facts = described_class.new(path).facts.to_s
      popper = facts[/gadget\("csu_popper", (\d+)\)/, 1]
      mov = facts[/gadget\("csu_mov", (\d+)\)/, 1]
      # the challenge binary: __libc_csu_init at 0x400640, the epilogue
      # at 0x40069a, the mov block at 0x400680
      expect(popper.to_i).to eq(0x40069a)
      expect(mov.to_i).to eq(0x400680)
    end
  end
end
