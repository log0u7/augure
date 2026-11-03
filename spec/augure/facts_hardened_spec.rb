# frozen_string_literal: true

require "augure"
require "stringio"

# The measured brainforge MR5 failures, hardened. P1: the suggest merge
# path deduplicates identical lines (first-emission order preserved) and
# caps the accepted suggested facts, naming every dropped line loudly -
# augure must be safe on its own, without a pilot filter. P2: every fact
# carries its provenance class (measured vs suggested), and the explain
# payload reports the fact-source for every evidence fact.
RSpec.describe "hardened facts: suggest merge + provenance" do
  let(:warnings) { StringIO.new }

  def merge(text, cap: Augure::Facts::SUGGEST_CAP)
    facts = Augure::Facts.new
    stats = facts.merge_suggested(text, cap: cap, warn: warnings.method(:puts))
    [facts, stats, warnings.string]
  end

  describe "P1: noisy ingestion rejection" do
    it "collapses 800 identical lines into one fact and names the dropped count loudly" do
      facts, stats, warning = merge("vuln(\"fmtstr\").\n" * 800)
      expect(facts.rel("vuln")).to eq([["fmtstr"]])
      expect(stats[:accepted]).to eq(1)
      expect(stats[:dropped]).to eq(799)
      expect(warning).to match(/dropped 799/)
    end

    it "caps distinct suggested facts at the documented default (16) and warns" do
      text = (1..20).map { |i| "plt(\"fn#{i}\").\n" }.join
      facts, stats, warning = merge(text)
      expect(facts.rel("plt").size).to eq(16)
      expect(stats[:accepted]).to eq(16)
      expect(stats[:dropped]).to eq(4)
      expect(warning).to match(/dropped 4/)
      expect(warning).to match(/cap 16/)
    end

    it "keeps first-emission order when deduplicating" do
      facts, stats, = merge("plt(\"b\").\nplt(\"a\").\nplt(\"b\").\nplt(\"c\").\n")
      expect(facts.rel("plt")).to eq([%w[b], %w[a], %w[c]])
      expect(stats[:duplicates]).to eq(1)
      expect(stats[:accepted]).to eq(3)
    end

    it "honours an explicit cap override" do
      text = (1..5).map { |i| "plt(\"fn#{i}\").\n" }.join
      facts, stats, warning = merge(text, cap: 2)
      expect(facts.rel("plt").size).to eq(2)
      expect(stats[:dropped]).to eq(3)
      expect(warning).to match(/dropped 3/)
    end

    it "does not let repeats of already-measured facts consume the cap" do
      facts = Augure::Facts.parse("plt(\"puts\").\n")
      suggest = "plt(\"puts\").\n" + (1..17).map { |i| "plt(\"fn#{i}\").\n" }.join
      stats = facts.merge_suggested(suggest, warn: warnings.method(:puts))
      # the repeat adds no new fact, so 17 fresh facts would exceed the
      # cap: only 16 accepted, and the repeat is counted as a duplicate
      expect(stats[:accepted]).to eq(16)
      expect(stats[:dropped]).to eq(2)
      expect(stats[:duplicates]).to eq(1)
    end

    it "still rejects malformed suggested lines with the line number" do
      expect { Augure::Facts.new.merge_suggested("not_a_predicate(\"x\").\n") }
        .to raise_error(Augure::UnknownPredicate, /line 1/)
      expect { Augure::Facts.new.merge_suggested("plt(\"b\nroken\").\n") }
        .to raise_error(Augure::MalformedFact, /line 1/)
    end
  end

  describe "P2: fact provenance classes" do
    it "tags profiler facts as measured" do
      facts = Augure::Facts.parse("plt(\"printf\").\n")
      expect(facts.source_of("plt", "printf")).to eq(%i[measured])
      expect(facts.measured?("plt", "printf")).to be(true)
    end

    it "tags suggest facts as suggested and keeps them distinguishable" do
      facts = Augure::Facts.parse("plt(\"printf\").\n")
      facts.merge_suggested("vuln(\"uaf\").\n", warn: warnings.method(:puts))
      expect(facts.source_of("vuln", "uaf")).to eq(%i[suggested])
      expect(facts.measured?("vuln", "uaf")).to be(false)
    end

    it "records both classes when the profiler and the suggest step agree" do
      facts = Augure::Facts.parse("plt(\"printf\").\n")
      facts.merge_suggested("plt(\"printf\").\n", warn: warnings.method(:puts))
      expect(facts.source_of("plt", "printf")).to eq(%i[measured suggested])
    end

    it "reports the fact-source for every evidence fact in explain" do
      decision = Augure::Pipeline.analyze(
        facts: "nx(\"true\").\npie(\"false\").\nplt(\"system\").\n",
        suggest: "vuln(\"sof\").\n"
      )
      prov = decision[:explain][:provenance]["ret2plt"].first
      sources = prov[:evidence_sources]
      expect(prov[:evidence]).to include(%w[vuln sof])
      expect(sources).to include("suggested")
      expect(sources).to include("measured")
    end
  end
end
