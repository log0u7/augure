# frozen_string_literal: true

require "augure"
require "json"
require "tmpdir"

RSpec.describe Augure::Facts do
  let(:text) do
    <<~FACTS
      nx("true").
      pie("false").
      gadget("pop_rdi_ret", 4198400).
      plt("puts").
      vuln_hint("unsafe_func:gets").
    FACTS
  end

  describe ".parse" do
    it "parses single string atoms" do
      facts = described_class.parse("nx(\"true\").\n")
      expect(facts.rel("nx")).to eq([["true"]])
    end

    it "parses multi-arg relations with integer atoms" do
      facts = described_class.parse("gadget(\"pop_rdi_ret\", 4198400).\n")
      expect(facts.rel("gadget")).to eq([["pop_rdi_ret", 4198400]])
    end

    it "groups facts by relation" do
      facts = described_class.parse(text)
      expect(facts.rel("plt")).to eq([["puts"]])
      expect(facts.rel("gadget")).to eq([["pop_rdi_ret", 4198400]])
    end

    it "keeps insertion order inside a relation" do
      two = described_class.parse("plt(\"puts\").\nplt(\"read\").\n")
      expect(two.rel("plt")).to eq([["puts"], ["read"]])
    end

    it "ignores blank lines and // comments" do
      noisy = "// comment\n\nnx(\"true\").\n  \npie(\"false\").\n"
      facts = described_class.parse(noisy)
      expect(facts.size).to eq(2)
    end

    it "raises UnknownPredicate on an undeclared predicate" do
      expect {
        described_class.parse("not_a_predicate(\"x\").\n")
      }.to raise_error(Augure::UnknownPredicate, /not_a_predicate/)
    end

    it "raises MalformedFact with the line number on bad syntax" do
      expect {
        described_class.parse("nx(\"true\").\nxyz garbage line\n")
      }.to raise_error(Augure::MalformedFact, /line 2/)
    end

    it "rejects rules (:-) with MalformedFact" do
      expect {
        described_class.parse("applicable(\"rop\") :- vuln(\"sof\").\n")
      }.to raise_error(Augure::MalformedFact, /rules are not facts/)
    end

    it "rejects wrong arity for a declared predicate" do
      expect {
        described_class.parse("nx(\"true\", \"extra\").\n")
      }.to raise_error(Augure::MalformedFact, /arity/)
    end

    it "rejects unquoted atoms for string positions" do
      expect { described_class.parse("nx(true).\n") }
        .to raise_error(Augure::MalformedFact, /string atom/)
    end

    it "rejects integers where the schema expects a string" do
      expect { described_class.parse("nx(1).\n") }
        .to raise_error(Augure::MalformedFact, /string atom/)
    end

    it "parses the entire frozen CTF corpus (24 targets)" do
      corpus = JSON.parse(File.read(File.join(__dir__, "../fixtures/ctf_corpus.json")))
      entries = corpus["suites"].values.flatten
      expect(entries.size).to eq(24)

      entries.each do |entry|
        facts = described_class.parse(entry["facts"])
        expect(facts).not_to be_nil
        # round-trip stability: parse(emit) == parse
        expect(described_class.parse(facts.to_s).to_s).to eq(facts.to_s)
      end
    end

    it "accepts the extended vocabulary: fmtstr_read, reloc_writable, dt_lazy, limited_stack" do
      text = "fmtstr_read(\"true\").\nreloc_writable(\"true\").\n" \
             "dt_lazy(\"true\").\nlimited_stack(\"true\").\n"
      facts = described_class.parse(text)
      expect(facts.rel("fmtstr_read")).to eq([["true"]])
      expect(facts.rel("reloc_writable")).to eq([["true"]])
      expect(facts.rel("dt_lazy")).to eq([["true"]])
      expect(facts.rel("limited_stack")).to eq([["true"]])
    end
  end

  describe ".from_file" do
    it "reads facts from disk" do
      path = File.join(Dir.tmpdir, "augure_spec_facts_#{Process.pid}.facts")
      File.write(path, text)
      facts = described_class.from_file(path)
      expect(facts.rel("nx")).to eq([["true"]])
    ensure
      File.delete(path)
    end
  end

  describe "#[]" do
    it "aliases rel" do
      expect(described_class.parse(text)["nx"]).to eq([["true"]])
    end
  end

  describe "#merge" do
    it "returns a new Facts with combined relations" do
      a = described_class.parse("nx(\"true\").\n")
      b = described_class.parse("pie(\"false\").\n")
      merged = a.merge(b)
      expect(merged.rel("nx")).to eq([["true"]])
      expect(merged.rel("pie")).to eq([["false"]])
      expect(a.rel("pie")).to be_nil
    end
  end
end
