# frozen_string_literal: true

require "augure"
require "augure/pack_loader"

RSpec.describe "the shipped technique packs" do
  let(:packs) { Augure::PackLoader.load_dir(File.expand_path("../../packs", __dir__)) }
  let(:names) { packs.map(&:technique) }

  it "ships the corpus-extending techniques plus the canonical example" do
    expect(names).to contain_exactly(
      "ret2csu_v2", "house_force", "house_orange", "house_botcake",
      "unsorted_bin_attack", "fastbin_hook", "ret2dlresolve_x86",
      "got_partial_overwrite", "brop", "ret2partial_overwrite", "one_gadget",
      "orw", "banner_leak", "jop", "large_bin_attack", "house_of_apple2",
      "setcontext_srop", "uaf_tcache", "ret2vdso", "got_partial_overwrite_deref",
      "callme", "callme_eval2", "ret2plt_eval2", "srop_eval2"
    )
  end

  it "takes the callme top-1 only through the documented pack verdict" do
    # the callme corpus shape, with the pop3 gadget the eval twin's
    # rule keys on: with the pack loaded, the verdict is callme_eval2
    facts = "nx(\"true\").\npie(\"false\").\ncanary(\"false\").\nrelro(\"partial\").\n" \
      "plt(\"callme_one\").\nplt(\"callme_two\").\nplt(\"callme_three\").\nplt(\"puts\").\n" \
      "plt(\"memset\").\nplt(\"read\").\nplt(\"printf\").\nplt(\"exit\").\n" \
      "gadget(\"pop_rdi_rsi_rdx_ret\", 4198400).\ngadget(\"pop_rdi_ret\", 4198400).\n" \
      "gadget(\"ret_align\", 4198400).\nvuln_hint(\"unsafe_func:gets\")."
    decision = Augure::Pipeline.analyze(facts: facts, packs: packs, plan: false)
    expect(decision[:ranking].first).to eq("callme_eval2")
  end

  it "teaches the orw ROP variant: openat/read/write off the facts" do
    # the harder twin's filter allows openat(257) only; the chain aims
    # the .data anchors (flag_path, out_buf) with the pop/syscall set
    build = packs.find { |p| p.technique == "orw" }.build
    expect(build["variants"].map { |v| v["name"] }).to eq(%w[rop stack])
    rop = build["variants"].first["layout"].flatten
    expect(rop).to include("const:257", "gadget:syscall_ret",
      "gadget:pop_rax_ret", "sym:flag_path", "sym:out_buf")
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
    "one_gadget" => %{libc_present("true").\nnx("true").},
    "ret2plt_eval2" => %{vuln("sof").\nnx("true").\npie("false").\nplt("system").\nsym_addr("arg_cmd", 4196032).},
    "srop_eval2" => %{vuln("sof").\nnx("true").\npie("false").\ngadget("sigreturn", 4198846).\nsym_addr("sh_cmd", 4210744).}
  }.each do |technique, facts|
    it "makes #{technique} applicable on its fact shape" do
      decision = Augure::Pipeline.analyze(facts: facts, packs: packs, plan: false)
      expect(decision[:applicable]).to include(technique)
      provenance = decision[:explain][:provenance][technique]
      expect(provenance.first[:origin]).to eq(technique)
    end
  end
end
