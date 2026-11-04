# frozen_string_literal: true

require "augure"
require "augure/pack_loader"

# The MR6 uaf twins (lab targets uaf_train_a/b, run 2026-11-04): the
# profiler emits malloc/free PLT facts but NEVER a vuln("uaf") fact -
# that signal only ever came from the suggest LLM, and without it the
# uaf_tcache technique was unreachable (0/40 rollouts on the twins).
# The static rule keys on what the profiler measures: malloc + free in
# the PLT and NO profiled vuln fact (the heap packs keep their verdicts
# where the profiler DID tag vuln("heap")).
RSpec.describe "uaf_tcache static rule (MR6 twins)" do
  let(:packs) { Augure::PackLoader.load_dir(File.expand_path("../../packs", __dir__)) }

  def decide(facts)
    Augure::Pipeline.analyze(facts: facts, packs: packs, plan: false)
  end

  def rules_for(decision, technique)
    decision[:explain][:provenance].fetch(technique).map { |p| p[:rule] }
  end

  shared_examples "proposes uaf_tcache" do
    it "ranks uaf_tcache first from the measured facts alone" do
      decision = decide(facts)
      expect(decision[:applicable]).to include("uaf_tcache")
      expect(decision[:ranking].first).to eq("uaf_tcache")
    end

    it "proposes it through the static rule" do
      decision = decide(facts)
      expect(rules_for(decision, "uaf_tcache")).to include(:app_uaf_tcache_static)
    end
  end

  describe "uaf_train_a (no-PIE twin, win() statically visible)" do
    let(:facts) do
      <<~FACTS
        nx("true").
        pie("false").
        canary("false").
        relro("partial").
        plt("free").
        plt("__libc_start_main").
        plt("puts").
        plt("printf").
        plt("fputs").
        plt("strcspn").
        plt("fgets").
        plt("strtoull").
        plt("malloc").
        plt("fflush").
        plt("setvbuf").
        plt("fopen").
        plt("exit").
        plt("fwrite").
        gadget("ret_align", 4198422).
        target_function("true").
        win_symbol("win", 4198886).
      FACTS
    end

    include_examples "proposes uaf_tcache"
  end

  describe "uaf_train_b (PIE twin, win() leaked at runtime)" do
    let(:facts) do
      <<~FACTS
        nx("true").
        pie("true").
        canary("false").
        relro("partial").
        plt("free").
        plt("__libc_start_main").
        plt("puts").
        plt("printf").
        plt("fputs").
        plt("strcspn").
        plt("fgets").
        plt("strtoull").
        plt("malloc").
        plt("fflush").
        plt("setvbuf").
        plt("fopen").
        plt("atoi").
        plt("exit").
        plt("fwrite").
        plt("__cxa_finalize").
        gadget("ret_align", 4118).
      FACTS
    end

    include_examples "proposes uaf_tcache"
  end

  describe "corpus neighbors the rule must NOT steal" do
    it "tcache_tear stays heap_tcache (the profiler tagged vuln heap)" do
      decision = decide(<<~FACTS)
        nx("true").
        pie("false").
        canary("true").
        relro("full").
        plt("malloc").
        plt("free").
        plt("printf").
        plt("read").
        vuln("heap").
        libc_present("true").
        allocator("tcache").
        glibc_minor(26).
      FACTS
      expect(decision[:applicable]).not_to include("uaf_tcache")
      expect(decision[:ranking].first).to eq("heap_tcache")
    end

    it "old_dayz stays heap_fastbin" do
      decision = decide(<<~FACTS)
        nx("true").
        pie("false").
        canary("false").
        relro("partial").
        plt("malloc").
        plt("free").
        plt("printf").
        plt("read").
        vuln("heap").
        libc_present("true").
        allocator("ptmalloc2").
        glibc_minor(23).
      FACTS
      expect(decision[:applicable]).not_to include("uaf_tcache")
      expect(decision[:ranking].first).to eq("heap_fastbin")
    end
  end
end
