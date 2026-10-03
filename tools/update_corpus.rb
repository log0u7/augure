# frozen_string_literal: true

# Corpus update tool: applies the documented vocabulary extension.
#
# Rules of engagement:
#   - untouched entries must stay byte-identical (the parity contract)
#   - truth updates carry a documented justification
#   - applicable/ranking/selected are recomputed by the engine, never
#     hand-written
#
# Run: bundle exec ruby tools/update_corpus.rb

require "json"
require_relative "../lib/augure"

CORPUS = File.expand_path("../lib/augure/ctf_corpus.json", __dir__)

corpus = JSON.parse(File.read(CORPUS))
before = JSON.parse(corpus.to_json) # deep copy for the regression assert

# --- 1. Fact additions (documented challenge properties) ------------------
find = lambda do |suite, name|
  corpus["suites"][suite].find { |e| e["name"] == name }
end

pivot = find.call("ropemporium", "pivot")
pivot["facts"] = pivot["facts"].chomp("\n") + "\nlimited_stack(\"true\").\n"

# --- 2. Truth updates (documented justifications) -------------------------
RET2CSU_REASON = "the documented intended technique is ret2csu " \
                 "(__libc_csu_init popper/mov, official ROP Emporium " \
                 "solution); the previous vocabulary collapsed it into rop"
PIVOT_REASON = "the documented intended technique is stack_pivot (xchg " \
               "rsp,rax onto a second chain because the stack does not fit " \
               "it, official ROP Emporium solution); the previous vocabulary " \
               "collapsed it into rop"

find.call("ropemporium", "ret2csu")["truth"] = "ret2csu"
find.call("ropemporium", "ret2csu")["truth_update"] = RET2CSU_REASON
find.call("ropemporium", "pivot")["truth"] = "stack_pivot"
find.call("ropemporium", "pivot")["truth_update"] = PIVOT_REASON

FORMAT4_REASON = "protostar format4's documented goal is the GOT write " \
                 "(%n on printf's GOT, official hints and write-ups); the " \
                 "previous vocabulary only had fmtstr_write for it"
find.call("protostar", "format4")["truth"] = "got_overwrite"
find.call("protostar", "format4")["truth_update"] = FORMAT4_REASON

# --- 3. New protostar entry (format1: the leak exercise) ------------------
corpus["suites"]["protostar"] << {
  "suite" => "protostar",
  "name" => "format1",
  "facts" => "vuln(\"fmtstr\").\nfmtstr_read(\"true\").\nrelro(\"none\").\n",
  "truth" => "fmtstr_leak"
}

# --- 4. Phoenix suite (exploit.education/phoenix, public documented) ------
phoenix = [
  ["stack-three", "vuln_hint(\"unsafe_func:strcpy\").\ntarget_function(\"true\").\n", "ret2func"],
  ["stack-five", "vuln_hint(\"unsafe_func:gets\").\nnx(\"false\").\nshellcode_input(\"true\").\n", "shellcode"],
  ["format-one", "vuln(\"fmtstr\").\n", "fmtstr_write"],
  ["format-two", "vuln(\"fmtstr\").\n", "fmtstr_write"],
  ["format-three", "vuln(\"fmtstr\").\n", "fmtstr_write"],
  ["format-four", "vuln(\"fmtstr\").\ngot_overwrite_target(\"true\").\n", "got_overwrite"],
  ["heap-zero", "vuln(\"heap\").\nfunction_pointer_on_heap(\"true\").\nglibc_minor(27).\n", "heap_overwrite"],
  ["heap-one", "vuln(\"heap\").\nfunction_pointer_on_heap(\"true\").\nglibc_minor(27).\n", "heap_overwrite"]
]

common = "pie(\"false\").\ncanary(\"false\").\nrelro(\"partial\").\n"
corpus["suites"]["phoenix"] = phoenix.map do |name, extra, truth|
  {
    "suite" => "phoenix",
    "name" => name,
    "facts" => "nx(\"true\").\n#{common}#{extra}",
    "truth" => truth
  }
end

# --- 5. Recompute every entry through the engine --------------------------
# The current default priors (AG + EXTENDED + KB) become the frozen meta
# priors. Existing techniques' priors are untouched by this iteration, so
# the regression assert below must hold.
meta_priors = Augure::Pipeline.default_priors
corpus["meta"]["priors"] = meta_priors
bandit_template = Augure::Pipeline.selector(priors: meta_priors)

corpus["suites"].each_value do |entries|
  entries.each do |entry|
    result = Augure::Pipeline.analyze(facts: entry["facts"], priors: meta_priors)
    entry["applicable"] = result[:applicable]
    entry["ranked"] = bandit_template.ranking_of(result[:applicable])
      .map { |t, m| [t, m.round(10)] }
    entry["selected"] = entry["ranked"].first&.first
  end
end

# --- 6. Regression assert: untouched entries byte-identical ---------------
TOUCHED = %w[ret2csu pivot format4].freeze
regressions = []
before["suites"].each do |suite, entries|
  entries.each do |entry|
    next if suite == "phoenix" || TOUCHED.include?(entry["name"])

    new_entry = corpus["suites"][suite].find { |e| e["name"] == entry["name"] }
    if new_entry["applicable"] != entry["applicable"] ||
        new_entry["ranked"] != entry["ranked"]
      regressions << "#{suite}/#{entry["name"]}"
    end
  end
end
unless regressions.empty?
  abort "REGRESSION (corpus not written): #{regressions.join(", ")}"
end

# --- 7. Write -------------------------------------------------------------
corpus["meta"]["vocabulary_extended"] = "iteration 2: fmtstr_leak, " \
  "ret2dlresolve, ret2csu, stack_pivot, got_overwrite; Phoenix suite added"
File.write(CORPUS, JSON.pretty_generate(corpus))
n = corpus["suites"].values.sum(&:size)
puts "corpus written: #{n} targets across #{corpus["suites"].size} suites"
