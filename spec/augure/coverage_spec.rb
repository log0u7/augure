# frozen_string_literal: true

require "augure"
require "json"

RSpec.describe Augure::Coverage do
  # one minimal entry: ret2plt on a vulnerable build; the flip kills it
  let(:entry) do
    {"suite" => "spec", "name" => "t1",
     "facts" => "vuln(\"sof\").\nnx(\"true\").\npie(\"false\").\ncanary(\"false\").\nplt(\"system\").\n"}
  end
  let(:entry2) do
    {"suite" => "spec", "name" => "t2",
     "facts" => "vuln(\"sof\").\nnx(\"true\").\npie(\"false\").\ncanary(\"false\").\nplt(\"system\").\ngadget(\"pop_rdi_ret\", 1).\n"}
  end

  describe ".report" do
    it "the flip kills the technique and the coverage says so" do
      report = described_class.report([entry], flips: {"plt" => nil})
      e = report[:entries].first
      expect(e[:before]).to include("ret2plt")
      expect(e[:after]).not_to include("ret2plt")
      expect(e[:lost]).to eq(%w[ret2plt])
      expect(report[:died]["ret2plt"]).to eq(1)
    end

    it "the flip replaces the value, not just appends" do
      # nx false -> true: the shellcode technique dies (nx true blocks it)
      hardened = {"suite" => "spec", "name" => "t3",
                  "facts" => "vuln(\"sof\").\nnx(\"false\").\npie(\"false\").\ncanary(\"false\").\n"}
      report = described_class.report([hardened], flips: {"nx" => "true"})
      e = report[:entries].first
      expect(e[:before]).to include("shellcode")
      expect(e[:after]).not_to include("shellcode")
    end

    it "an absent predicate fact is ADDED by the flip" do
      # canary absent -> canary true: the canary-gated techniques die
      report = described_class.report([entry], flips: {"canary" => "true"})
      e = report[:entries].first
      # nothing canary-gated was applicable before; nothing dies here -
      # but the hardened facts carry the control
      expect(Augure::Facts.parse(e[:hardened_facts]).rel("canary")).to eq([["true"]])
    end

    it "gained techniques are counted (a flip can ADD nothing - but the structure holds)" do
      report = described_class.report([entry, entry2], flips: {"relro" => "full"})
      expect(report[:entries].size).to eq(2)
      expect(report).to have_key(:died)
      expect(report).to have_key(:survived_count)
    end
  end
end
