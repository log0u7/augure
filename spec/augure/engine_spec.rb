# frozen_string_literal: true

require "augure"
require "json"

RSpec.describe Augure::Engine do
  def facts_for(text)
    Augure::Facts.parse(text)
  end

  def applicable(text)
    described_class.new(facts_for(text)).run.applicable
  end

  describe "derived relations" do
    it "derives sof from gets/strcpy hints" do
      f = facts_for("vuln_hint(\"unsafe_func:gets\").\nvuln_hint(\"unsafe_func:strcpy\").\n")
      r = described_class.new(f).run
      expect(r.derived("vuln")).to contain_exactly(["sof"])
    end

    it "derives fmtstr from printf/sprintf hints" do
      f = facts_for("vuln_hint(\"unsafe_func:printf\").\n")
      expect(described_class.new(f).run.derived("vuln")).to eq([["fmtstr"]])
    end

    it "derives gadget families from gadget types" do
      f = facts_for(
        "gadget(\"pop_rdi_ret\", 1).\n" \
        "gadget(\"mov_deref_write\", 2).\n" \
        "gadget(\"syscall_ret\", 3).\n" \
        "gadget(\"int80_ret\", 4).\n"
      )
      r = described_class.new(f).run
      expect(r.derived("has_reg_control")).to eq([["true"]])
      expect(r.derived("has_write_primitive")).to eq([["true"]])
      expect(r.derived("has_syscall_gadget")).to eq([["true"]])
      expect(r.derived("enough_gadgets")).to eq([["true"]])
    end
  end

  describe "technique rules" do
    it "fires shellcode only when NX off, no canary, return not filtered" do
      on = "vuln(\"sof\").\nnx(\"false\").\ncanary(\"false\").\n"
      expect(applicable(on)).to eq(["shellcode"])

      filtered = on + "return_addr_filtered(\"true\").\n"
      expect(applicable(filtered)).to be_empty
    end

    it "fires ret2func on win function without PIE" do
      f = "vuln(\"sof\").\nnx(\"true\").\npie(\"false\").\ntarget_function(\"true\").\n"
      expect(applicable(f)).to eq(["ret2func"])
    end

    it "fires ret2plt on system@plt without PIE" do
      f = "vuln(\"sof\").\nnx(\"true\").\npie(\"false\").\nplt(\"system\").\n"
      expect(applicable(f)).to eq(["ret2plt"])
    end

    it "fires ret2libc from __libc_start_main OR libc_present, once" do
      via_plt = "vuln(\"sof\").\nplt(\"__libc_start_main\").\n"
      via_flag = "vuln(\"sof\").\nlibc_present(\"true\").\n"
      both = via_flag + via_plt
      expect(applicable(via_plt)).to eq(["ret2libc"])
      expect(applicable(via_flag)).to eq(["ret2libc"])
      expect(applicable(both).count("ret2libc")).to eq(1)
    end

    it "fires rop with register or write control under NX" do
      reg = "vuln(\"sof\").\nnx(\"true\").\ngadget(\"pop_rdi_ret\", 1).\n"
      write = "vuln(\"sof\").\nnx(\"true\").\ngadget(\"mov_deref_write\", 1).\n"
      expect(applicable(reg)).to eq(["rop"])
      expect(applicable(write)).to eq(["rop"])
    end

    it "fires srop on sigreturn frame + syscall gadget" do
      f = "vuln(\"sof\").\nsigreturn_frame(\"true\").\ngadget(\"syscall_ret\", 1).\n"
      expect(applicable(f)).to eq(["srop"])
    end

    it "fires ret2plt_leak only with NX+PIE+puts+reg control" do
      f = "vuln(\"sof\").\nnx(\"true\").\npie(\"true\").\nplt(\"puts\").\n" \
          "gadget(\"pop_rdi_ret\", 1).\n"
      # rop also fires here (Python-identical: NX + gadget supply).
      expect(applicable(f)).to eq(%w[rop ret2plt_leak])
    end

    it "fires fmtstr_write on format-string vuln regardless of NX" do
      expect(applicable("vuln(\"fmtstr\").\npie(\"false\").\ncanary(\"false\").\n"))
        .to eq(["fmtstr_write"])
    end

    it "splits heap techniques by allocator and glibc minor" do
      tcache = "vuln(\"heap\").\nallocator(\"tcache\").\n"
      glibc = "vuln(\"heap\").\nglibc_minor(27).\n"
      fastbin = "vuln(\"heap\").\nglibc_minor(24).\n"
      overwrite = "vuln(\"heap\").\nallocator(\"dlmalloc\").\n"
      fp = "vuln(\"heap\").\nfunction_pointer_on_heap(\"true\").\n"
      expect(applicable(tcache)).to eq(["heap_tcache"])
      expect(applicable(glibc)).to eq(["heap_tcache"])
      expect(applicable(fastbin)).to eq(["heap_fastbin"])
      expect(applicable(overwrite)).to eq(["heap_overwrite"])
      expect(applicable(fp)).to eq(["heap_overwrite"])
    end

    it "applies defaults: NX true, PIE true, canary false when absent" do
      # No nx fact -> default true -> shellcode impossible, rop possible.
      f = "vuln(\"sof\").\ngadget(\"pop_rdi_ret\", 1).\n"
      expect(applicable(f)).to eq(["rop"])
      # canary absent -> default false, but NX default true -> still no shellcode.
    end
  end

  describe "auditability" do
    it "records rule provenance per applicable technique" do
      f = "vuln(\"sof\").\nnx(\"true\").\npie(\"false\").\nplt(\"system\").\n"
      r = described_class.new(facts_for(f)).run
      prov = r.provenance("ret2plt")
      expect(prov).not_to be_empty
      expect(prov.first[:rule]).to eq(:app_ret2plt)
      expect(prov.first[:evidence]).to include(["vuln", "sof"])
      expect(prov.first[:evidence]).to include(["plt", "system"])
    end
  end

  describe "extended vocabulary techniques" do
    it "fires fmtstr_leak when the read primitive or a protection exists" do
      read = "vuln(\"fmtstr\").\nfmtstr_read(\"true\").\n"
      pie = "vuln(\"fmtstr\").\npie(\"true\").\n"
      canary = "vuln(\"fmtstr\").\ncanary(\"true\").\n"
      expect(applicable(read)).to include("fmtstr_leak")
      expect(applicable(pie)).to include("fmtstr_leak")
      expect(applicable(canary)).to include("fmtstr_leak")
      # no read primitive and no protection to bypass: the leak has no value
      bare = "vuln(\"fmtstr\").\npie(\"false\").\ncanary(\"false\").\n"
      expect(applicable(bare)).to eq(["fmtstr_write"])
    end

    it "fires ret2dlresolve on lazy binding with writable relocation" do
      f = "vuln(\"sof\").\nnx(\"true\").\npie(\"false\").\n" \
          "dt_lazy(\"true\").\nreloc_writable(\"true\").\n"
      expect(applicable(f)).to eq(["ret2dlresolve"])

      full = f.sub("dt_lazy(\"true\")", "dt_lazy(\"false\")")
      expect(applicable(full)).to be_empty
    end

    it "fires ret2csu when csu gadgets exist" do
      f = "vuln(\"sof\").\nnx(\"true\").\ngadget(\"csu_popper\", 1).\n" \
          "gadget(\"csu_mov\", 2).\n"
      expect(applicable(f)).to include("ret2csu")
    end

    it "fires stack_pivot on xchg gadget with limited stack" do
      f = "vuln(\"sof\").\nnx(\"true\").\nlimited_stack(\"true\").\n" \
          "gadget(\"xchg_rsp_rax\", 1).\n"
      expect(applicable(f)).to include("stack_pivot")

      # No stack constraint: ROP directly is the documented better choice.
      roomy = "vuln(\"sof\").\nnx(\"true\").\ngadget(\"xchg_rsp_rax\", 1).\n"
      expect(applicable(roomy)).not_to include("stack_pivot")
    end

    it "fires got_overwrite when the GOT target is viable and not full RELRO" do
      f = "vuln(\"sof\").\nnx(\"true\").\ngot_overwrite_target(\"true\").\n" \
          "relro(\"partial\").\n"
      expect(applicable(f)).to include("got_overwrite")

      # fmtstr path: %n writes the GOT entry, no NX constraint
      fmt = "vuln(\"fmtstr\").\ngot_overwrite_target(\"true\").\nrelro(\"partial\").\n"
      expect(applicable(fmt)).to include("got_overwrite")

      full = f.sub("relro(\"partial\")", "relro(\"full\")")
      expect(applicable(full)).not_to include("got_overwrite")
    end
  end

  describe "CTF corpus conformance" do
    it "reproduces the frozen Python applicable set byte-for-byte" do
      corpus = JSON.parse(File.read(File.join(__dir__, "../../lib/augure/ctf_corpus.json")))
      entries = corpus["suites"].values.flatten

      entries.each do |entry|
        r = described_class.new(Augure::Facts.parse(entry["facts"])).run
        expect(r.applicable).to eq(entry["applicable"]),
          "#{entry["suite"]}/#{entry["name"]}: got #{r.applicable}, " \
          "expected #{entry["applicable"]}"
      end
    end
  end
end

RSpec.describe "cmp conditions from data (packs)" do
  it "accepts string comparison ops - YAML carries strings, not symbols" do
    facts = Augure::Facts.parse("glibc_minor(31).\n")
    rule = Augure::Rules::Rule.new("spec_cmp", [:x, :ok],
      [[:cmp, "glibc_minor", "ge", 29]], "spec", nil)
    result = Augure::Engine.new(facts, rules: [rule]).run
    expect(result.derived_rels[:x]).to eq([[:ok]])
  end
end
