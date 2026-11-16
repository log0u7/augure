# frozen_string_literal: true

# Adds the MR7 technique-target entries (the 7 new lab classes) to the
# corpus. Each entry carries pack_verdict: with the packs loaded, the
# documented pack technique must rank FIRST on its own target (the
# corpus guard enforces this at every pack load).
#
# Fact-base discipline mirrors the existing entries: only the facts the
# decision may consume at strike time. The vuln-class fact is omitted
# on the leak-stage targets (one_gadget, setcontext_srop) whose pack
# rules consume post-leak facts; the brop entry carries the remote
# oracle facts only - the blind class has no binary to profile.
#
# Run: bundle exec ruby tools/add_mr7_lab_entries.rb

require "json"
require_relative "../lib/augure"

CORPUS = File.expand_path("../lib/augure/ctf_corpus.json", __dir__)
corpus = JSON.parse(File.read(CORPUS))
# frozen fields are the BUILT-IN decision (packs excluded), matching
# every existing entry; pack_verdict is checked separately by the guard
# with the packs loaded.
base_priors = Augure::Pipeline.default_priors
bandit = Augure::Pipeline.selector(priors: base_priors)

entries = [
  # brop: the blind class - no binary, only the remote fault oracle.
  ["brop",
    "nx(\"true\").\nremote(\"true\").\nverified(\"remote\").\n"],
  # one_gadget: post-leak strike - the libc base is known, the gamble
  # is the one_gadget constraint vs a full chain.
  ["one_gadget",
    "nx(\"true\").\nlibc_present(\"true\").\n"],
  # got_partial_overwrite: partial RELRO + a known writable GOT target;
  # the write primitive itself comes from the model's dynamic stage.
  ["got_partial_overwrite",
    "nx(\"true\").\nrelro(\"partial\").\ngot_overwrite_target(\"true\").\n"],
  # ret2partial_overwrite: PIE, no canary, NO leak primitive - the
  # 2-byte page hop is the only move.
  ["ret2partial_overwrite",
    "nx(\"true\").\npie(\"true\").\ncanary(\"false\").\nvuln(\"sof\").\n"],
  # jop: register-driven dispatch - the xchg pivot plus pop gadgets,
  # no chain terminus of the classic kinds.
  ["jop",
    "nx(\"true\").\npie(\"false\").\ncanary(\"false\").\nvuln(\"sof\").\n" \
    "gadget(\"pop_rdi_ret\", 4198806).\ngadget(\"xchg_rsp_rax\", 4198966).\n"],
  # ret2vdso: PIE with NO syscall gadget of its own - the loader-mapped
  # vDSO page is the only syscall source.
  ["ret2vdso",
    "nx(\"true\").\npie(\"true\").\nrelro(\"full\").\nplt(\"puts\").\nvuln(\"sof\").\n"],
  # setcontext_srop: the sigreturn door with the libc base known.
  ["setcontext_srop",
    "nx(\"true\").\ngadget(\"syscall\", 4198810).\n" \
    "sigreturn_frame(\"true\").\nlibc_present(\"true\").\n"]
]

lab = corpus["suites"]["lab"] ||= []
entries.each do |name, facts|
  lab.reject! { |e| e["name"] == name } # idempotent re-runs
  result = Augure::Pipeline.analyze(facts: facts, priors: base_priors, plan: false)
  ranked = bandit.ranking_of(result[:applicable]).map { |t, m| [t, m.round(10)] }
  lab << {
    "suite" => "lab",
    "name" => name,
    "facts" => facts,
    "applicable" => result[:applicable],
    "ranked" => ranked,
    "selected" => ranked.first&.first,
    "truth" => name,
    "pack_verdict" => name
  }
end

File.write(CORPUS, JSON.pretty_generate(corpus))
puts "lab suite entries: #{lab.size}"
