# frozen_string_literal: true

require "augure-profiler"
require_relative "support/binary_builder"

RSpec.describe AugureProfiler::GadgetHunt do
  it "hunts a real binary: pop chains with in-section addresses" do
    bin = ProfilerBinaryBuilder.vulnerable
    gadgets = described_class.hunt(bin)
    expect(gadgets).not_to be_empty
    pop = gadgets.find { |g| g[:type].start_with?("pop_") }
    expect(pop).not_to be_nil
    expect(pop[:addr]).to be_an(Integer).and be > 0
  end

  it "finds the multi-instruction gadgets the byte patterns cannot see" do
    skip "the ropemporium cache is not present" unless File.file?("/tmp/opencode/ropemporium_parity/write4/write4")
    types = described_class.hunt("/tmp/opencode/ropemporium_parity/write4/write4")
      .map { |g| g[:type] }
    expect(types).to include("pop_r14_r15_ret")
    expect(types).to include("pop_rsi_r15_ret")
    expect(types).to include("mov_deref_write")
  end

  it "classifies only ret-terminated chains with safe semantics" do
    chain = described_class.classify(["pop rsi", "pop r15", "ret"])
    expect(chain).to eq("pop_rsi_r15_ret")
    expect(described_class.classify(["pop rdi", "call rax", "ret"])).to be_nil
  end

  it "declines chains that die on a killer instruction" do
    di = double(instruction: double(to_s: "call rax", opname: "call", bin_length: 3))
    allow(described_class).to receive(:decode_at).and_return(di)
    expect(described_class.decode_chain(Metasm::X64.new, Metasm::EncodedData.new("AAAA"), 0, 0)).to be_nil
  end
end
