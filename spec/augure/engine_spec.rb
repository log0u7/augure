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
      expect(applicable("vuln(\"fmtstr\").\n")).to eq(["fmtstr_write"])
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

  describe "CTF corpus conformance" do
    it "reproduces the frozen Python applicable set byte-for-byte" do
      corpus = JSON.parse(File.read(File.join(__dir__, "../fixtures/ctf_corpus.json")))
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
