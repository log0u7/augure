# frozen_string_literal: true

require "open3"
require "json"
require "tmpdir"

RSpec.describe "augure DX surface" do
  let(:exe) { File.expand_path("../exe/augure", __dir__) }
  let(:ret2win) { File.expand_path("../examples/ret2win.facts", __dir__) }

  describe "--version on the three executables" do
    it "reports the augure version" do
      out, _err, status = Open3.capture3(exe, "--version")
      expect(status.exitstatus).to eq(0)
      expect(out).to include("augure #{Augure::VERSION}")
    end

    it "reports the benchmark version" do
      exe_bench = File.expand_path("../exe/augure-benchmark", __dir__)
      out, _err, status = Open3.capture3(exe_bench, "--version")
      expect(status.exitstatus).to eq(0)
      expect(out).to include("augure")
    end

    it "reports the profiler version" do
      exe_prof = File.expand_path("../profiler/exe/augure-profile", __dir__)
      out, _err, status = Open3.capture3(exe_prof, "--version")
      expect(status.exitstatus).to eq(0)
      expect(out).to include("augure-profiler")
    end
  end

  describe "augure doctor" do
    it "reports ok on the dev checkout (corpus self-test passes)" do
      out, _err, status = Open3.capture3(exe, "doctor")
      expect(status.exitstatus).to eq(0)
      expect(out).to include("ok    corpus self-test")
      expect(out).to include("selected: ret2func")
      expect(out).not_to include("FAIL")
    end

    it "reports solvers as optional" do
      out, _err, _status = Open3.capture3(exe, "doctor")
      expect(out).to match(/solvers.*optional/)
    end
  end

  describe "versioned machine payload" do
    it "stamps schema: augure/decision@1" do
      out, _err, status = Open3.capture3(exe, "analyze", ret2win, "--json")
      expect(status.exitstatus).to eq(0)
      expect(JSON.parse(out)["schema"]).to eq("augure/decision@1")
    end
  end

  describe "augure rules" do
    it "lists the rules-as-data table for humans" do
      out, _err, status = Open3.capture3(exe, "rules")
      expect(status.exitstatus).to eq(0)
      expect(out).to include("app_ret2plt")
      expect(out).to include("system@plt imported: call it directly, no leak")
    end
  end

  describe "augure explain <technique>" do
    it "shows the rules and the knowledge-base entry" do
      out, _err, status = Open3.capture3(exe, "explain", "ret2plt")
      expect(status.exitstatus).to eq(0)
      expect(out).to include("app_ret2plt")
      expect(out).to include("success_rate")
    end

    it "fails with the known techniques on an unknown one" do
      _out, err, status = Open3.capture3(exe, "explain", "nope")
      expect(status.exitstatus).not_to eq(0)
      expect(err).to include("nope")
    end
  end
end
