# frozen_string_literal: true

require "open3"
require "json"
require "tmpdir"

RSpec.describe "exe/augure" do
  let(:exe) { File.expand_path("../../exe/augure", __dir__) }
  let(:split_entry) do
    corpus = JSON.parse(File.read(File.join(__dir__, "../../lib/augure/ctf_corpus.json")))
    corpus["suites"]["ropemporium"].find { |e| e["name"] == "split" }
  end

  it "smoke: emits a valid JSON decision from a facts file" do
    Dir.mktmpdir do |dir|
      path = File.join(dir, "split.facts")
      File.write(path, split_entry["facts"])
      stdout, _err, status = Open3.capture3(exe, "analyze", path, "--json", "--seed", "42")
      expect(status.exitstatus).to eq(0)
      decision = JSON.parse(stdout)
      expect(decision["selected"]).to eq("ret2plt")
      expect(decision["applicable"]).to include("rop")
    end
  end

  it "smoke: reads facts from stdin" do
    stdout, _err, status = Open3.capture3(exe, "analyze", "-", "--json", stdin_data: split_entry["facts"])
    expect(status.exitstatus).to eq(0)
    expect(JSON.parse(stdout)["selected"]).to eq("ret2plt")
  end

  it "explains the decision in human form" do
    stdout, _err, status = Open3.capture3(exe, "analyze", "-", stdin_data: split_entry["facts"])
    expect(status.exitstatus).to eq(0)
    expect(stdout).to include("applicable: ret2plt, rop")
    expect(stdout).to include("ret2plt <- app_ret2plt")
  end

  it "fails loudly on malformed facts" do
    _out, err, status = Open3.capture3(exe, "analyze", "-", stdin_data: "garbage(")
    expect(status.exitstatus).not_to eq(0)
    expect(err).to match(/malformed fact/i)
  end

  it "smoke: reproduces the frozen corpus decision end to end" do
    corpus = JSON.parse(File.read(File.join(__dir__, "../../lib/augure/ctf_corpus.json")))
    corpus["suites"].values.flatten.each do |entry|
      stdout, _err, status = Open3.capture3(exe, "analyze", "-", "--json", stdin_data: entry["facts"])
      expect(status.exitstatus).to eq(0), "#{entry["suite"]}/#{entry["name"]} exit"
      expect(JSON.parse(stdout)["ranking"].first).to eq(entry["selected"]),
        "#{entry["suite"]}/#{entry["name"]} ranking"
    end
  end
end
