# frozen_string_literal: true

require "augure"
require "json"

RSpec.describe Augure::Bandit do
  let(:priors) do
    {
      "ret2plt" => [15, 5], "rop" => [10, 10], "ret2func" => [16, 4],
      "shellcode" => [5, 13], "fmtstr_write" => [12, 8], "ret2libc" => [2, 18]
    }
  end

  describe "Beta sampling" do
    it "is deterministic for a given seed" do
      a = described_class::Arm.new(15, 5, rng: Random.new(42))
      b = described_class::Arm.new(15, 5, rng: Random.new(42))
      expect(a.sample).to eq(b.sample)
    end

    it "stays within (0, 1) across many draws" do
      arm = described_class::Arm.new(2.5, 7.5, rng: Random.new(1))
      draws = Array.new(500) { arm.sample }
      expect(draws).to all(be_between(0.000001, 0.999999))
    end

    it "converges on the true mean (alpha / alpha+beta)" do
      arm = described_class::Arm.new(30, 70, rng: Random.new(7))
      mean = Array.new(4000) { arm.sample }.sum / 4000.0
      expect(mean).to be_between(0.26, 0.34)
    end
  end

  describe "#mean and #rankings" do
    it "ranks by prior mean, descending, deterministic" do
      bandit = described_class.new(priors: priors)
      expect(bandit.rankings).to eq(%w[ret2func ret2plt fmtstr_write rop shellcode ret2libc])
      expect(bandit.arm("ret2plt").mean).to eq(0.75)
    end
  end

  describe "#select" do
    it "picks only among verified techniques" do
      bandit = described_class.new(priors: priors, rng: Random.new(42))
      choice = bandit.select(%w[shellcode rop])
      expect(%w[shellcode rop]).to include(choice)
    end

    it "auto-arms unknown techniques with neutral (1, 1)" do
      bandit = described_class.new(priors: priors, rng: Random.new(42))
      bandit.select(%w[ret2csu])
      expect(bandit.arm("ret2csu").alpha).to eq(1)
      expect(bandit.arm("ret2csu").beta).to eq(1)
    end

    it "returns nil when nothing is verified" do
      expect(described_class.new(priors: priors).select([])).to be_nil
    end

    it "is deterministic under a fixed seed" do
      a = described_class.new(priors: priors, rng: Random.new(42)).select(%w[rop ret2plt ret2func])
      b = described_class.new(priors: priors, rng: Random.new(42)).select(%w[rop ret2plt ret2func])
      expect(a).to eq(b)
    end
  end

  describe "#feedback" do
    it "increments alpha on success, beta on failure" do
      bandit = described_class.new(priors: priors)
      bandit.feedback("rop", true)
      bandit.feedback("rop", false)
      expect(bandit.arm("rop").alpha).to eq(11)
      expect(bandit.arm("rop").beta).to eq(11)
    end

    it "records the audit history" do
      bandit = described_class.new(priors: priors)
      bandit.feedback("rop", true)
      expect(bandit.history).to include({technique: "rop", success: true})
    end
  end

  describe "CTF corpus conformance" do
    it "reproduces the frozen Python ranking and selection" do
      corpus = JSON.parse(File.read(File.join(__dir__, "../../lib/augure/ctf_corpus.json")))
      priors = corpus["meta"]["priors"]

      corpus["suites"].values.flatten.each do |entry|
        bandit = described_class.new(priors: priors)
        ranked = entry["applicable"].each_with_index.map { |t, i| [t, bandit.arm(t).mean, i] }
          .sort_by { |(_, m, i)| [-m, i] }
          .map { |(t, m, _)| [t, m] }
        expected_ranked = entry["ranked"]
        expect(ranked.map(&:first)).to eq(expected_ranked.map(&:first)),
          "#{entry["suite"]}/#{entry["name"]} ranking order"
        ranked.each_with_index do |(_, mean), i|
          expect(mean.round(10)).to eq(expected_ranked[i][1]),
            "#{entry["suite"]}/#{entry["name"]} rank #{i} mean"
        end
        expect(ranked.first&.first).to eq(entry["selected"]),
          "#{entry["suite"]}/#{entry["name"]} selected"
      end
    end
  end
end
