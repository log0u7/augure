# frozen_string_literal: true

require "augure"
require "augure/pack_loader"

RSpec.describe "the shipped technique packs" do
  let(:packs) { Augure::PackLoader.load_dir(File.expand_path("../../packs", __dir__)) }
  let(:names) { packs.map(&:technique) }

  it "ships the ten corpus-extending techniques plus the canonical example" do
    expect(names).to contain_exactly("ret2csu_v2", "house_force", "house_orange",
      "house_botcake", "unsorted_bin_attack", "fastbin_hook", "ret2dlresolve_x86",
      "got_partial_overwrite", "brop", "ret2partial_overwrite", "one_gadget")
  end

  it "passes the corpus guard: no frozen verdict moves" do
    expect { Augure::PackLoader.corpus_guard(packs) }.not_to raise_error
  end

  {
    "house_force" => %{vuln("heap").\nallocator("dlmalloc").},
    "house_botcake" => %{vuln("heap").\nallocator("tcache").\nglibc_minor(31).},
    "ret2dlresolve_x86" => %{dt_lazy("true").\nreloc_writable("true").\npie("false").},
    "got_partial_overwrite" => %{relro("partial").\ngot_overwrite_target("true").},
    "brop" => %{remote("true").\nverified("remote").\nnx("true").},
    "ret2partial_overwrite" => %{pie("true").\nvuln("sof").\ncanary("false").},
    "one_gadget" => %{libc_present("true").\nnx("true").}
  }.each do |technique, facts|
    it "makes #{technique} applicable on its fact shape" do
      decision = Augure::Pipeline.analyze(facts: facts, packs: packs, plan: false)
      expect(decision[:applicable]).to include(technique)
      provenance = decision[:explain][:provenance][technique]
      expect(provenance.first[:origin]).to eq(technique)
    end
  end
end
