# frozen_string_literal: true

require "augure"
require "json"

RSpec.describe Augure::KnowledgeBase do
  let(:kb) { described_class.new }

  describe "seed corpus" do
    it "ships 17 exploitation-pattern entries" do
      expect(described_class.corpus.size).to eq(17)
    end

    it "indexes them on load" do
      expect(kb.size).to eq(17)
    end
  end

  describe "TF-IDF query" do
    it "ranks the most similar entry first" do
      results = kb.query("system is imported and pop rdi gadget present, no PIE")
      expect(results.first.doc["technique"]).to eq("ret2plt")
      expect(results.first[:score]).to be > 0.3
    end

    it "filters by technique" do
      results = kb.query("leak the libc base", technique: "srop")
      expect(results.map { |r| r.doc["technique"] }).to all(eq("srop"))
    end

    it "returns [] when nothing matches above threshold" do
      expect(kb.query("zzzqqq")).to eq([])
    end
  end

  describe "prior calibration" do
    it "converts corpus success rates to Beta pseudo-counts (N=10)" do
      priors = described_class.priors
      expect(priors["ret2plt"][0]).to be_within(1e-9).of(16.7)
      expect(priors["ret2plt"][1]).to be_within(1e-9).of(3.3)
    end

    it "aggregates across entries of the same technique" do
      priors = described_class.priors
      entries = described_class.corpus.select { |e| e["technique"] == "rop" }
      alpha = entries.sum { |e| e["success_rate"] * 10 }
      expect(priors["rop"][0]).to be_within(1e-9).of(alpha)
    end
  end

  describe "transition model" do
    it "maps techniques to the techniques they unlock" do
      transitions = described_class.transitions
      expect(transitions["fmtstr_write"]).to eq(%w[ret2libc rop])
      expect(transitions["heap_tcache"]).to eq(["fmtstr_write"])
    end
  end
end
