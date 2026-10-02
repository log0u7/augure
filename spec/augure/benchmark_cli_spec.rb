# frozen_string_literal: true

require "json"
require "open3"
require "tmpdir"

RSpec.describe "exe/augure-benchmark" do
  let(:exe) { File.expand_path("../../exe/augure-benchmark", __dir__) }
  let(:corpus) { File.expand_path("../fixtures/ctf_corpus.json", __dir__) }

  it "prints per-suite concordance and exits 0 at full concordance" do
    stdout, _err, status = Open3.capture3(exe, corpus)
    expect(status.exitstatus).to eq(0)
    expect(stdout).to include("Top-1 concordance: 34/34")
    expect(stdout).to match(/ropemporium\s+8\/8/)
    expect(stdout).to match(/phoenix\s+8\/8/)
  end

  it "fails when concordance drops below the threshold" do
    Dir.mktmpdir do |dir|
      corrupted = File.join(dir, "corpus.json")
      c = JSON.parse(File.read(corpus))
      entry = c["suites"]["ropemporium"].first
      entry["truth"] = "nonexistent_technique"
      File.write(corrupted, JSON.generate(c))
      _out, _err, status = Open3.capture3(exe, corrupted)
      expect(status.exitstatus).to eq(1)
    end
  end
end
