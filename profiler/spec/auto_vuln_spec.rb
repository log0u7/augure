# frozen_string_literal: true

require "augure-profiler"
require_relative "support/binary_builder"

RSpec.describe "the profiler's own vuln facts (the knowledge the binary carries)" do
  it "emits vuln(sof) with the sink and the function from the static frame read" do
    bin = ProfilerBinaryBuilder.vulnerable
    facts = AugureProfiler::Profiler.new(bin).facts.to_s
    expect(facts).to match(/vuln\("sof"\)/)
    expect(facts).to match(/sink\("strcpy"\)/)
    expect(facts).to match(/vuln_function\("vuln_copy"\)/)
  end

  it "stays silent when the only sized copy cannot reach the return slot" do
    bin = ProfilerBinaryBuilder.bounded_memcpy
    facts = AugureProfiler::Profiler.new(bin).facts.to_s
    expect(facts).not_to match(/vuln\("sof"\)/)
  end

  it "emits vuln(sof) + sink when a sized copy's length is not a bounded immediate" do
    bin = ProfilerBinaryBuilder.unbounded_memcpy
    facts = AugureProfiler::Profiler.new(bin).facts.to_s
    expect(facts).to match(/vuln\("sof"\)/)
    expect(facts).to match(/sink\("memcpy"\)/)
  end

  it "keeps printf-with-a-constant-format out of the vuln facts" do
    bin = ProfilerBinaryBuilder.printf_constant
    facts = AugureProfiler::Profiler.new(bin).facts.to_s
    expect(facts).not_to match(/vuln\("fmtstr"\)/)
  end

  it "emits vuln(fmtstr) + fmtstr_read when the format lives on the stack" do
    bin = ProfilerBinaryBuilder.printf_stack
    facts = AugureProfiler::Profiler.new(bin).facts.to_s
    expect(facts).to match(/vuln\("fmtstr"\)/)
    expect(facts).to match(/fmtstr_read\("true"\)/)
  end

  it "stays silent on a sized stdin read whose immediate cannot reach the return slot" do
    bin = ProfilerBinaryBuilder.bounded_read
    facts = AugureProfiler::Profiler.new(bin).facts.to_s
    expect(facts).not_to match(/vuln\("sof"\)/)
  end
end
