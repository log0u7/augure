# frozen_string_literal: true

require "augure"
require "json"

RSpec.describe Augure::Mcts do
  describe "STAGE_MODEL" do
    it "gates techniques behind their required capabilities" do
      caps = Augure::Mcts.caps
      expect(described_class.available(caps, ["ret2libc", "shellcode"])).to eq(["shellcode"])
    end

    it "unlocks ret2libc after a libc leak" do
      caps = Augure::Mcts.transition(Augure::Mcts.caps, "fmtstr_leak")
      expect(described_class.available(caps, ["ret2libc", "rop"])).to contain_exactly("ret2libc", "rop")
    end

    it "detects terminal states" do
      shell = Augure::Mcts.transition(Augure::Mcts.caps, "shellcode")
      expect(described_class.terminal?(shell)).to be(true)
      expect(described_class.terminal?(Augure::Mcts.caps)).to be(false)
    end
  end

  describe "rollout" do
    it "returns 1.0 on an already-terminal state" do
      shell = Augure::Mcts.transition(Augure::Mcts.caps, "shellcode")
      expect(described_class.rollout(shell, ["shellcode"], rng: Random.new(1))).to eq(1.0)
    end

    it "returns 0.0 on a dead end" do
      expect(described_class.rollout(Augure::Mcts.caps, [], rng: Random.new(1))).to eq(0.0)
    end

    it "returns the terminal technique's own success at depth 0" do
      # shellcode alone, terminal: reward = 0.90 (own success), not a flat 1.0
      r = described_class.rollout(Augure::Mcts.caps, ["shellcode"], rng: Random.new(3))
      expect(r).to eq(0.9)
    end

    it "discounts deeper rewards within the theoretical bound" do
      # Two-hop chain: 0.75 (leak) * 0.85 (terminal at depth 1, discounted).
      # The leak stays available mid-rollout, so draw the range over seeds.
      draws = Array.new(60) do
        described_class.rollout(Augure::Mcts.caps, %w[fmtstr_leak ret2libc],
          rng: Random.new(it))
      end
      expect(draws).to all(be > 0.0)
      expect(draws.max).to be_within(1e-9).of(0.75 * 0.85 * 0.97)
    end
  end

  describe "plan" do
    it "plans the leak first when terminals require libc_base" do
      first, path = described_class.plan(%w[fmtstr_leak ret2libc rop rop_nocontext],
        iterations: 2000, seed: 42)
      expect(first).to eq("fmtstr_leak")
      expect(path).to eq(%w[fmtstr_leak ret2libc])
    end

    it "picks the direct terminal when one exists" do
      first, path = described_class.plan(%w[shellcode ret2plt], iterations: 2000, seed: 42)
      expect(%w[shellcode ret2plt]).to include(first)
      expect(path.size).to eq(1)
    end

    it "is deterministic for a fixed seed" do
      a = described_class.plan(%w[fmtstr_leak ret2libc], iterations: 500, seed: 7)
      b = described_class.plan(%w[fmtstr_leak ret2libc], iterations: 500, seed: 7)
      expect(a).to eq(b)
    end
  end

  describe "CTF corpus conformance" do
    it "reproduces the frozen Python first move and path" do
      corpus = JSON.parse(File.read(File.join(__dir__, "../../lib/augure/ctf_corpus.json")))

      corpus["mcts"].each do |entry|
        first, path = described_class.plan(entry["allowed"],
          iterations: corpus.dig("meta", "mcts_iterations"),
          seed: corpus.dig("meta", "mcts_seed"))
        expect(first).to eq(entry["documented_first"]),
          "#{entry["name"]}: first move #{first} != #{entry["documented_first"]}"
        expect(path.first(entry["documented_chain"].size))
          .to eq(entry["documented_chain"]),
            "#{entry["name"]}: path #{path.inspect}"
      end
    end
  end
end
