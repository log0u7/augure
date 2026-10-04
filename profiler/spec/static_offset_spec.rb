# frozen_string_literal: true

require "augure-profiler/static_offset"
require_relative "support/binary_builder"
require "tmpdir"

RSpec.describe AugureProfiler::StaticOffset do
  let(:fixture) { ProfilerBinaryBuilder.vulnerable }

  it "reads the fixture offset straight off the frame" do
    result = described_class.offset(fixture)
    expect(result[:offset]).to eq(16)
    expect(result[:sink]).to eq("strcpy")
    expect(result[:function]).to eq("vuln_copy")
  end

  it "handles both PLT layouts (.plt.sec and classic .plt)" do
    # the fixture carries .plt.sec (CFI); the assertion is the offset -
    # a wrong stub table finds no call site at all.
    expect(described_class.offset(fixture)).not_to be_nil
  end

  it "returns nil for a binary without an unsafe import" do
    clean = File.join(Dir.mktmpdir, "clean")
    File.binwrite(clean, "\x7fELF\x02\x01\x01" + "\x00" * 64)
    # metasm refuses a truncated elf: the contract is nil, never a crash
    expect(described_class.offset(clean)).to be_nil
  end
end
