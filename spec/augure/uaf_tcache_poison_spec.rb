# frozen_string_literal: true

require "augure"
require "augure/pack_loader"

RSpec.describe "Augure uaf_tcache gate (corroboration fix)" do
  let(:base_facts) do
    # Sof target, NO malloc/free in PLT - not a heap target by measurement
    "vuln(\"sof\").\nnx(\"true\").\npie(\"false\").\n"
  end

  let(:poison_suggestion) do
    # What a poisoned LLM would suggest on a non-UAF target
    "vuln(\"uaf\").\nallocator(\"tcache\").\n"
  end

  let(:uaf_pack) do
    Augure::PackLoader.load_file(File.expand_path("../../packs/uaf_tcache.yml", __dir__))
  end

  it "does not open uaf_tcache when vuln(uaf) is suggested-only (not measured)" do
    base = Augure::Facts.parse(base_facts)
    base.merge_suggested(poison_suggestion)

    result = Augure::Pipeline.analyze(facts: base, seed: 42, packs: [uaf_pack])

    expect(result[:applicable]).not_to include("uaf_tcache"),
      "uaf_tcache must not fire on a suggested-only vuln(uaf); got #{result[:applicable].inspect}"
  end

  it "opens uaf_tcache when vuln(uaf) is measured (profiler-confirmed)" do
    base = Augure::Facts.parse(base_facts + "vuln(\"uaf\").\nallocator(\"tcache\").\n")
    result = Augure::Pipeline.analyze(facts: base, seed: 42, packs: [uaf_pack])

    expect(result[:applicable]).to include("uaf_tcache"),
      "uaf_tcache should fire when vuln(uaf) is measured; got #{result[:applicable].inspect}"
  end
end
