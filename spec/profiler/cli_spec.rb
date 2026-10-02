# frozen_string_literal: true

require "open3"
require "tmpdir"
require_relative "support/binary_builder"

RSpec.describe "exe/augure-profile" do
  let(:exe) { File.expand_path("../../profiler/exe/augure-profile", __dir__) }

  it "smoke: emits facts to stdout and the engine decides" do
    dir = BinaryBuilder.build
    binary = File.join(dir, "vuln_nx_off_nopie")
    stdout, _err, status = Open3.capture3(exe, binary)
    expect(status.exitstatus).to eq(0)
    expect(stdout).to include('nx("false").')

    result = Augure::Pipeline.analyze(facts: stdout, seed: 42)
    expect(result[:ranking].first).to eq("shellcode")
  end

  it "writes to -o and fails loudly on a non-ELF file" do
    dir = BinaryBuilder.build
    binary = File.join(dir, "vuln_nx_off_nopie")
    out = File.join(dir, "target.facts")
    _out, err, status = Open3.capture3(exe, binary, "-o", out)
    expect(status.exitstatus).to eq(0)
    expect(err).to include("wrote #{out}")

    _out, err, status = Open3.capture3(exe, "/etc/hostname")
    expect(status.exitstatus).not_to eq(0)
    expect(err).to match(/augure-profile:/)
  end
end
