# frozen_string_literal: true

require "augure"
require "json"

RSpec.describe Augure::Pipeline do
  let(:facts_text) do
    "nx(\"true\").\npie(\"false\").\ncanary(\"false\").\n" \
      "plt(\"system\").\ngadget(\"pop_rdi_ret\", 4198400).\n" \
      "vuln_hint(\"unsafe_func:gets\").\n"
  end

  describe ".analyze" do
    it "returns the full decision with provenance" do
      result = described_class.analyze(facts: facts_text)
      expect(result).to include(:applicable, :verified, :selected, :plan, :explain)
      expect(result[:applicable]).to include("ret2plt")
      expect(result[:selected]).to eq("ret2plt")
      prov = result[:explain][:provenance]["ret2plt"]
      expect(prov).not_to be_empty
      expect(prov.first[:rule]).to eq(:app_ret2plt)
      expect(prov.first[:evidence]).to include(["vuln", "sof"])
    end

    it "merges AG priors with KB priors" do
      # ret2plt: AG (15,5) + KB (16.7,3.3) = (31.7, 8.3) -> mean 0.7925
      bandit = described_class.selector
      expect(bandit.arm("ret2plt").alpha).to be_within(1e-9).of(31.7)
      expect(bandit.arm("ret2plt").mean.round(4)).to eq(0.7925)
    end

    it "accepts explicit priors overriding the defaults" do
      bandit = described_class.selector(priors: {"rop" => [1, 1]})
      expect(bandit.arm("rop").alpha).to eq(1)
    end

    it "is deterministic for a fixed seed" do
      a = described_class.analyze(facts: facts_text, seed: 42)
      b = described_class.analyze(facts: facts_text, seed: 42)
      expect(a).to eq(b)
    end

    it "returns an empty decision when nothing is applicable" do
      result = described_class.analyze(facts: "relro(\"none\").\n")
      expect(result[:applicable]).to be_empty
      expect(result[:selected]).to be_nil
    end
  end

  describe "CTF corpus smoke (selection parity)" do
    it "ranks the documented technique first on all 24 targets (deterministic)" do
      corpus = JSON.parse(File.read(File.join(__dir__, "../fixtures/ctf_corpus.json")))
      corpus["suites"].values.flatten.each do |entry|
        result = described_class.analyze(facts: entry["facts"])
        expect(result[:ranking].first).to eq(entry["selected"]),
          "#{entry["suite"]}/#{entry["name"]}: #{result[:ranking].inspect}"
      end
    end
  end
end
