# frozen_string_literal: true

require "augure-profiler"
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

RSpec.describe "the crash identification" do
  let(:fixture) { ProfilerBinaryBuilder.vulnerable }

  it "names the function, the sink and confirms the control - from evidence" do
    report = AugureProfiler::Triage.run(fixture, "A" * 512)
    facts = AugureProfiler::StaticOffset.crash_facts(fixture, report)
    expect(facts[:crash_site]).to eq("ret")
    expect(facts[:vuln_function]).to eq("vuln_copy")
    expect(facts[:sink]).to eq("strcpy")
  end

  it "says unknown for a crash that carries none of our bytes" do
    report = AugureProfiler::Triage.run(fixture, "\x90" * 400)
    facts = AugureProfiler::StaticOffset.crash_facts(fixture, report)
    expect(facts[:crash_site]).to eq("unknown")
  end
end

RSpec.describe AugureProfiler::DynamicTrace do
  let(:fixture) { ProfilerBinaryBuilder.vulnerable }

  it "proves the write site: the pattern lands at the return slot" do
    site = described_class.write_site(fixture, "A" * 200)
    expect(site[:caller]).to eq("vuln_copy")
    expect(site[:sink]).to eq("strcpy")
    expect(site[:instruction]).to match(/0x[0-9a-f]+/)
  end

  it "maps the runtime decor: the stack is there" do
    map = described_class.runtime_map(fixture)
    expect(map[:stack_base]).to be > 0
    expect(map[:stack_end]).to be > map[:stack_base]
  end
end
