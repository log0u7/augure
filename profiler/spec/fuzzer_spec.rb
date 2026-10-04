# frozen_string_literal: true

require "augure-profiler"
require_relative "support/binary_builder"
require "tmpdir"

RSpec.describe AugureProfiler::Fuzzer do
  let(:binary) { ProfilerBinaryBuilder.vulnerable }

  describe ".run with the built-in Ruby mutator" do
    it "discovers the crash on the vulnerable binary" do
      crashes = described_class.run(binary, seed: "AAAA", inputs: 40, max_len: 256)
      expect(crashes).not_to be_empty
      expect(crashes.first[:input].bytesize).to be > 8
    end

    it "is deterministic for a fixed seed" do
      a = described_class.run(binary, seed: "AAAA", inputs: 20, max_len: 128, rng: Random.new(7))
      b = described_class.run(binary, seed: "AAAA", inputs: 20, max_len: 128, rng: Random.new(7))
      expect(a.map { |c| c[:input] }).to eq(b.map { |c| c[:input] })
    end
  end

  describe "RubyMutator" do
    it "produces mutated variants of the seed" do
      mutations = AugureProfiler::RubyMutator.mutate("AAAA", 20, Random.new(1), max_len: 128)
      expect(mutations.size).to eq(20)
      expect(mutations.uniq.size).to be > 1
    end
  end

  describe "facts from a crash" do
    it "emits the stack-overflow facts the engine consumes" do
      crashes = described_class.run(binary, seed: "AAAA", inputs: 40, max_len: 256)
      report = AugureProfiler::Triage.run(binary, crashes.first[:input], backend: :gdb)
      facts = AugureProfiler::Triage.facts(report)
      expect(facts).to include("vuln(\"sof\").\n")
    end
  end
end

RSpec.describe AugureProfiler::Triage do
  let(:dir) { Dir.mktmpdir }
  let(:binary) { ProfilerBinaryBuilder.vulnerable(dir) }
  let(:crash_input) { ("A" * 64).b }

  describe ".run with the gdb backend" do
    it "returns the signal and the registers on a fuzzer-discovered crash" do
      crashes = AugureProfiler::Fuzzer.run(binary, seed: "AAAA", inputs: 60, max_len: 256)
      skip "no crash discovered - triage needs an input that faults" if crashes.empty?

      report = described_class.run(binary, crashes.first[:input], backend: :gdb)
      expect(report[:signal]).to eq("SIGSEGV")
      expect(report[:registers]).to include("rip", "rsp")
    end
  end

  describe "backend resolution" do
    it "defaults to gdb (present on this host)" do
      expect(described_class.resolve_backend).to eq(:gdb)
    end

    it "raises a clear error when no backend exists" do
      allow(described_class).to receive(:system).and_return(false)
      expect { described_class.run(binary, crash_input) }
        .to raise_error(AugureProfiler::TriageError, /no triage backend/)
    end
  end

  describe ".gdb_command_parser (fixture-driven, no gdb needed)" do
    it "parses the signal, registers and faulting instruction from gdb output" do
      output = <<~GDB
        Program received signal SIGSEGV, Segmentation fault.
        0x0000000000401136 in vuln_copy ()
        rax            0x4141414141414141  4702111234474983745
        rsp            0x7fffffffe2d0      0x7fffffffe2d0
        rip            0x4141414141        0x4141414141
      GDB
      parsed = described_class.parse_gdb(output)
      expect(parsed[:signal]).to eq("SIGSEGV")
      expect(parsed[:registers]["rip"]).to eq("0x4141414141")
      expect(parsed[:fault_addr]).to eq("0x4141414141")
      # The crash address is input pattern bytes: register control.
      expect(parsed[:control]).to eq(:rip)
    end
  end
end

RSpec.describe "the cyclic offset" do
  it "builds a unique-3-gram pattern and finds the offset of its own bytes" do
    pattern = AugureProfiler::Triage.cyclic(400)
    expect(pattern.size).to eq(400)
    expect(pattern[0, 3]).to eq("aA0")
    [0, 7, 100, 391].each do |off|
      expect(AugureProfiler::Triage.cyclic_offset(pattern, pattern[off, 8])).to eq(off)
    end
  end

  it "finds the offset through the 32-bit truncation of the register" do
    pattern = AugureProfiler::Triage.cyclic(400)
    full = pattern[100, 8]
    truncated = full[0, 4] + "\x00\x00\x00\x00"
    expect(AugureProfiler::Triage.cyclic_offset(pattern, truncated)).to eq(100)
  end

  it "reads the real offset of the fixture binary under gdb" do
    skip "gdb not installed" unless system("sh", "-c", "command -v gdb >/dev/null")
    offset = AugureProfiler::Triage.offset(ProfilerBinaryBuilder.vulnerable)
    expect(offset).to be_a(Integer)
    expect(offset).to be > 0
  end
end
