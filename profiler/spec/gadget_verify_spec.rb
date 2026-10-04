# frozen_string_literal: true

require "augure-profiler/static_offset"
require_relative "support/binary_builder"
require "tmpdir"

RSpec.describe "gadget verification" do
  let(:fixture) { ProfilerBinaryBuilder.vulnerable }

  def verify(type, addr)
    AugureProfiler::StaticOffset.verify_gadget(fixture, type, addr)
  end

  it "confirms a real ret gadget" do
    # the fixture's frame: a ret sits in vuln_copy's epilogue
    expect(verify("ret_align", 0x1194)).to be(true)
  end

  it "rejects a gadget that does not decode to its advertised semantics" do
    expect(verify("ret_align", 0x1187)).to be(false) # the call to strcpy
    expect(verify("jmp_rsp", 0x1194)).to be(false)   # a ret is not a jmp
  end

  it "rejects addresses outside the executable sections" do
    expect(verify("ret_align", 0)).to be(false)
  end
end
