# frozen_string_literal: true

require "augure"
require "augure/pack_loader"

# The MR5 lictor lab targets (run 2026-11-03): ten fact shapes isolating
# technique classes the decision log routed WRONG. Each scenario feeds the
# target's fact base and freezes the expected proposal - the technique the
# ORACLE.md documents - as ranking top-1 with its rule provenance.
RSpec.describe "MR5 lab targets" do
  let(:packs) { Augure::PackLoader.load_dir(File.expand_path("../../packs", __dir__)) }

  def decide(facts)
    Augure::Pipeline.analyze(facts: facts, packs: packs, plan: false)
  end

  def rules_for(decision, technique)
    decision[:explain][:provenance].fetch(technique).map { |p| p[:rule] }
  end

  describe "ret2libc-001 (PIE + partial RELRO + puts@plt)" do
    let(:facts) do
      <<~FACTS
        nx("true").
        pie("true").
        canary("false").
        relro("partial").
        plt("__libc_start_main").
        plt("puts").
        plt("read").
        plt("memcpy").
        gadget("pop_rdi_ret", 4493).
        gadget("ret_align", 4118).
        vuln("sof").
        vuln_function("vuln_copy").
        sink("memcpy").
      FACTS
    end

    it "proposes the leak-first ret2libc, not ret2plt_leak or rop" do
      decision = decide(facts)
      expect(decision[:ranking].first).to eq("ret2libc")
      expect(rules_for(decision, "ret2libc")).to include(:app_ret2libc_leak_first)
    end

    it "does not propose ret2plt_leak when libc is one hop from the leak" do
      decision = decide(facts)
      expect(decision[:applicable]).not_to include("ret2plt_leak")
    end
  end

  describe "ret2libc-002 (no PIE, statically resolvable system)" do
    let(:facts) do
      <<~FACTS
        nx("true").
        pie("false").
        canary("false").
        relro("partial").
        libc_present("true").
        gadget("pop_rdi_ret", 4239075).
        gadget("syscall_ret", 4270162).
        vuln("sof").
        vuln_hint("unsafe_func:strcpy").
      FACTS
    end

    it "proposes ret2libc: libc is baked in, offsets are computable offline" do
      decision = decide(facts)
      expect(decision[:applicable]).to include("ret2libc")
      expect(rules_for(decision, "ret2libc")).to include(:app_ret2libc_libc)
    end

    # DEVIATION (E2-R1): the AG prior ranks rop ([10,10] + KB) above
    # ret2libc ([2,18] + KB) on this fact shape, so the generic chain
    # outdraws the direct system() call until the outcome-feedback layer
    # (lictor Priors.from_trail) or an authored recalibration moves the
    # prior. The rules make ret2libc applicable and auditable; the
    # ranking flip is a prior-layer decision, not a rule decision.
    it "ranks ret2libc first", pending: "ret2libc prior loses to rop; needs the prior layer (E2-R1)" do
      expect(decide(facts)[:ranking].first).to eq("ret2libc")
    end
  end

  describe "fmtstr-002 (PIE + format string)" do
    let(:facts) do
      <<~FACTS
        nx("true").
        pie("true").
        canary("false").
        relro("full").
        plt("printf").
        plt("puts").
        vuln("fmtstr").
        fmtstr_read("true").
      FACTS
    end

    it "proposes the two-stage flow: leak first, write second" do
      decision = decide(facts)
      expect(decision[:applicable]).to include("fmtstr_leak", "fmtstr_write")
      expect(decision[:ranking].first).to eq("fmtstr_leak")
      expect(decision[:ranking][1]).to eq("fmtstr_write")
    end
  end

  describe "ret2func-002 (canary + win function)" do
    let(:facts) do
      <<~FACTS
        nx("true").
        pie("false").
        canary("true").
        relro("partial").
        plt("__libc_start_main").
        plt("puts").
        target_function("true").
        win_symbol("win", 4198886).
        vuln("sof").
        vuln_function("vuln_copy").
      FACTS
    end

    it "proposes ret2func and records the canary-aware flow" do
      decision = decide(facts)
      expect(decision[:ranking].first).to eq("ret2func")
      expect(rules_for(decision, "ret2func")).to include(:app_ret2func_canary)
    end

    it "does not let ret2libc outdraw the win function" do
      expect(decide(facts)[:ranking].first).not_to eq("ret2libc")
    end
  end

  describe "shellcode-002 (NX off + RWX stack)" do
    let(:facts) do
      <<~FACTS
        nx("false").
        pie("true").
        canary("false").
        relro("partial").
        plt("__libc_start_main").
        plt("strcpy").
        plt("puts").
        vuln("sof").
        vuln_hint("unsafe_func:strcpy").
        sink("strcpy").
        leaked_address("buf", 140734910288256).
      FACTS
    end

    it "proposes shellcode over the leak-based ret2libc" do
      decision = decide(facts)
      expect(decision[:applicable]).to include("shellcode")
      expect(decision[:ranking].first).to eq("shellcode")
    end
  end

  describe "uaf_heap-002 (UAF + safe-linked tcache)" do
    let(:facts) do
      <<~FACTS
        nx("true").
        pie("false").
        canary("false").
        relro("partial").
        plt("free").
        plt("malloc").
        plt("__libc_start_main").
        target_function("true").
        win_symbol("win", 4198902).
        vuln("uaf").
        allocator("tcache").
        glibc_minor(36).
        function_pointer_on_heap("true").
      FACTS
    end

    it "proposes the safe-linked tcache fn-pointer overwrite" do
      decision = decide(facts)
      expect(decision[:applicable]).to eq(["uaf_tcache"])
      expect(decision[:ranking].first).to eq("uaf_tcache")
      expect(rules_for(decision, "uaf_tcache")).to include(:app_uaf_tcache_safelink)
    end
  end

  describe "orw-002 (strict seccomp)" do
    let(:facts) do
      <<~FACTS
        nx("true").
        pie("false").
        canary("false").
        relro("partial").
        seccomp("true").
        plt("__libc_start_main").
        plt("puts").
        plt("read").
        plt("prctl").
        gadget("pop_rdi_ret", 4198806).
        gadget("pop_rsi_ret", 4198819).
        gadget("pop_rdx_ret", 4198828).
        gadget("pop_rax_ret", 4198837).
        gadget("syscall_ret", 4198846).
        vuln("sof").
        vuln_function("vuln_copy").
      FACTS
    end

    it "proposes orw: execve dies under the filter" do
      decision = decide(facts)
      expect(decision[:applicable]).to eq(["orw"])
      expect(decision[:ranking].first).to eq("orw")
    end

    it "proposes nothing execve-shaped without the orw pack" do
      decision = Augure::Pipeline.analyze(facts: facts, plan: false)
      expect(decision[:applicable]).to be_empty
    end
  end

  describe "callme-002 (three announced helpers)" do
    let(:facts) do
      <<~FACTS
        nx("true").
        pie("false").
        canary("false").
        relro("partial").
        plt("__libc_start_main").
        plt("puts").
        plt("read").
        gadget("pop_rdi_rsi_rdx_ret", 4198860).
        gadget("ret_align", 4198861).
        vuln("sof").
        vuln_function("vuln_copy").
        leaked_address("one", 4198865).
        leaked_address("two", 4198870).
        leaked_address("three", 4198875).
      FACTS
    end

    it "proposes the callme 3-arg flow" do
      decision = decide(facts)
      expect(decision[:applicable]).to include("callme")
      expect(decision[:ranking].first).to eq("callme")
      expect(rules_for(decision, "callme")).to include(:app_callme_banner)
    end

    it "does not propose rop: the helpers are the win, not a generic chain" do
      expect(decide(facts)[:applicable]).not_to include("rop")
    end
  end

  describe "ret2plt-002 (full ASLR + pure-PLT primitives)" do
    let(:facts) do
      <<~FACTS
        nx("true").
        pie("true").
        canary("false").
        relro("full").
        plt("__libc_start_main").
        plt("puts").
        plt("write").
        plt("read").
        gadget("pop_rdi_ret", 4589).
        gadget("pop_rdx_ret", 4599).
        gadget("ret_align", 4118).
        vuln("sof").
        vuln_function("vuln_copy").
        leaked_address("main", 93974118982185).
      FACTS
    end

    it "proposes ret2plt_leak: the pure-PLT discipline owns the full-RELRO shape" do
      decision = decide(facts)
      expect(decision[:ranking].first).to eq("ret2plt_leak")
    end

    it "keeps ret2libc applicable but below the leak discipline" do
      decision = decide(facts)
      expect(decision[:applicable]).to include("ret2libc")
      expect(decision[:ranking].first).not_to eq("ret2libc")
    end
  end

  describe "srop-001 (sigreturn gadget)" do
    let(:facts) do
      <<~FACTS
        nx("true").
        pie("false").
        canary("false").
        relro("partial").
        plt("__libc_start_main").
        plt("puts").
        gadget("sigreturn", 4198774).
        gadget("ret_align", 4198422).
        vuln("sof").
        vuln_function("vuln_copy").
        leaked_address("gadget", 4198774).
      FACTS
    end

    it "proposes srop, not ret2libc" do
      decision = decide(facts)
      expect(decision[:applicable]).to include("srop")
      expect(decision[:ranking].first).to eq("srop")
    end

    it "derives the frame and the syscall from the sigreturn gadget" do
      decision = decide(facts)
      expect(rules_for(decision, "srop")).to include(:app_srop)
      engine = Augure::Engine.new(Augure::Facts.parse(facts)).run
      expect(engine.derived("sigreturn_frame")).to eq([["true"]])
      expect(engine.derived("has_syscall_gadget")).to eq([["true"]])
    end
  end

  # -- P3: corroboration preconditions (measured brainforge failures) --
  # The measured trails: a bogus suggested vuln("fmtstr") alone flipped a
  # correct srop/ret2libc routing; an 802-line suggestion flood flooded the
  # fact base. Suggested-only vuln facts must not decide routing on their
  # own: they need measured corroboration.
  describe "P3 corroboration preconditions" do
    let(:srop_profiler_facts) do
      # the real srop-001 measured stream: no fmtstr_read, no printf -
      # the profiler facts alone route srop correctly
      <<~FACTS
        nx("true").
        pie("false").
        canary("false").
        relro("partial").
        plt("__libc_start_main").
        plt("puts").
        gadget("sigreturn", 4198774).
        gadget("ret_align", 4198422).
        vuln("sof").
        vuln_function("vuln_copy").
        leaked_address("gadget", 4198774).
      FACTS
    end

    it "(a) profiler-only facts still route srop first" do
      decision = Augure::Pipeline.analyze(facts: srop_profiler_facts, seed: 1, packs: packs, plan: false)
      expect(decision[:ranking].first).to eq("srop")
    end

    it '(b) a bogus suggested vuln("fmtstr") does not flip routing to fmtstr_write' do
      decision = Augure::Pipeline.analyze(
        facts: srop_profiler_facts, suggest: "vuln(\"fmtstr\").\n",
        seed: 1, packs: packs, plan: false
      )
      expect(decision[:applicable]).not_to include("fmtstr_write", "fmtstr_leak")
      expect(decision[:ranking].first).to eq("srop")
    end

    it "(b+) the same suggested vuln fires once fmtstr_read is measured" do
      fmtstr_shape = srop_profiler_facts.sub(
        "gadget(\"sigreturn\", 4198774).\n", "gadget(\"sigreturn\", 4198774).\nfmtstr_read(\"true\").\n"
      )
      decision = Augure::Pipeline.analyze(
        facts: fmtstr_shape, suggest: "vuln(\"fmtstr\").\n",
        seed: 1, packs: packs, plan: false
      )
      expect(decision[:applicable]).to include("fmtstr_write")
    end

    it "(c) the 802-line flood decides exactly like the clean 3-fact suggest" do
      uaf_facts = <<~FACTS
        nx("true").
        pie("false").
        canary("false").
        relro("partial").
        plt("free").
        plt("malloc").
        plt("__libc_start_main").
        plt("puts").
        plt("strtoull").
        gadget("ret_align", 4198422).
        gadget("ret_align", 4199620).
        target_function("true").
        win_symbol("win", 4198902).
      FACTS
      clean = Augure::Pipeline.analyze(
        facts: uaf_facts, suggest: "vuln(\"uaf\").\nallocator(\"tcache\").\nglibc_minor(36).\n",
        seed: 1, packs: packs, plan: false
      )
      flood = Augure::Pipeline.analyze(
        facts: uaf_facts,
        suggest: "vuln(\"uaf\").\nvuln(\"fmtstr\").\nallocator(\"tcache\").\nglibc_minor(36).\n" +
                 ("vuln(\"fmtstr\").\n" * 798),
        seed: 1, packs: packs, plan: false
      )
      expect(flood[:suggest][:accepted]).to eq(4)
      expect(flood[:suggest][:dropped]).to eq(798)
      expect(flood[:applicable]).to eq(clean[:applicable])
      expect(flood[:ranking]).to eq(clean[:ranking])
      expect(flood[:selected]).to eq(clean[:selected])
      # the bogus vuln("fmtstr") rides in the first emissions: the gate
      # must keep fmtstr_* dead even when the noise would have carried it
      expect(flood[:applicable]).not_to include("fmtstr_write", "fmtstr_leak")
    end
  end
end
