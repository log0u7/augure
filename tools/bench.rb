# frozen_string_literal: true

# The reproducible speed benchmark: augure's decision path, the guard,
# the CLI boot, the profiler, the MCTS degenerate case. Run BEFORE and
# AFTER any optimization; the table is the comparison.
#   bundle exec ruby tools/bench.rb
$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
$LOAD_PATH.unshift File.expand_path("../profiler/lib", __dir__)
require "augure"
require "augure-profiler"
require "benchmark"
require "tmpdir"

def ms
  t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  yield
  ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0) * 1000).round(2)
end

rows = {}
facts = File.read(File.expand_path("../examples/split.facts", __dir__))

rows["decision (plan, MCTS)"] = "#{ms { 20.times { Augure::Pipeline.analyze(facts: facts) } } / 20.0} ms/dec"
rows["decision (no MCTS)"] = "#{ms { 20.times { Augure::Pipeline.analyze(facts: facts, plan: false) } } / 20.0} ms/dec"

packs = Augure::PackLoader.load_dir(File.expand_path("../packs", __dir__))
rows["pack load (20 packs)"] = "#{ms { Augure::PackLoader.load_dir(File.expand_path('../packs', __dir__)) }} ms"
rows["corpus guard (20 packs)"] = "#{ms { Augure::PackLoader.corpus_guard(packs) }} ms"

rows["facts parse"] = "#{ms { 50.times { Augure::Facts.parse(facts) } } / 50.0} ms/parse"

# the MCTS degenerate shape: a bounded 3-stage model where each stage
# provides a NEW capability (the tree grows ~iterations deep)
model = {
  "a" => [[], %w[cap_a], false, 0.5],
  "b" => [%w[cap_a], %w[cap_b], false, 0.5],
  "c" => [%w[cap_b], %w[cap_c], true, 0.9]
}.freeze
rows["MCTS degenerate (3 stages, 2000 it)"] = "#{ms { Augure::Mcts.plan(%w[a b c], iterations: 2000, seed: 1, model: model) }} ms"

# the profiler on real binaries
dir = Dir.mktmpdir
src = File.join(dir, "big.c")
File.write(src, "#include <stdio.h>\nint main(void){ puts(\"x\"); return 0; }\n")
bin_small = File.join(dir, "small")
system("gcc", "-o", bin_small, src, "-no-pie", out: File::NULL) || system("gcc", "-o", bin_small, src)
rows["profile /bin/ls (142KB .text)"] = "#{ms { AugureProfiler::Profiler.new('/bin/ls').facts }} ms"
big = "/usr/bin/gcc"
if File.exist?(big) && File.size(big) > 500_000
  rows["profile gcc-13 (#{File.size(big) / 1024}KB)"] = "#{ms { AugureProfiler::Profiler.new(big).facts }} ms"
end

puts
rows.each { |k, v| puts format("%-38s %s", k, v) }
