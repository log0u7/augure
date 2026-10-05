# frozen_string_literal: true

require "json"

module Augure
  # Loads and screens technique packs. The corpus guard is the armor's
  # last wall: with the packs loaded, every frozen corpus verdict must
  # stay identical - a pack that moves an existing decision is refused
  # at load time, not discovered in production.
  module PackLoader
    module_function

    def load_file(path)
      Pack.load_file(path)
    end

    def load_dir(dir)
      Dir.glob(File.join(dir, "*.{yml,yaml}")).sort.map { |p| Pack.load_file(p) }
    end

    # Belt and braces: new-heads-only already makes flips structurally
    # impossible; this proves it on every load.
    def corpus_guard(packs, corpus_path: nil)
      corpus_path ||= File.join(__dir__, "ctf_corpus.json")
      corpus = JSON.parse(File.read(corpus_path))
      base_priors = Pipeline.default_priors
      corpus["suites"].values.flatten.each do |entry|
        before = Pipeline.analyze(facts: entry["facts"], priors: base_priors, plan: false)
        after = Pipeline.analyze(facts: entry["facts"], priors: priors_with(packs, base_priors),
          packs: packs, plan: false)
        # A documented pack verdict is not a mover: the frozen entry may
        # say the built-in table has no answer for this target AND the
        # pack layer does (entry["pack_verdict"]) - the guard then
        # checks the pack answer ARRIVES, not that nothing changed. The
        # check holds only when that pack is among the loaded ones.
        if entry["pack_verdict"] && packs.any? { |p| p.technique == entry["pack_verdict"] }
          unless after[:ranking].first == entry["pack_verdict"]
            raise PackError,
              "corpus guard: pack(s) #{packs.map(&:technique).join(", ")} fail the documented " \
              "pack verdict on #{entry["suite"]}/#{entry["name"]} " \
              "(expected #{entry["pack_verdict"]}, got #{after[:ranking].first}) - refused"
          end
          next
        end
        # An empty frozen verdict has NOTHING to move: additive packs
        # extending it are the pack layer working (the documented case
        # was policed above by pack_verdict when its pack is loaded).
        next if before[:applicable].empty?

        # Additive packs may extend applicable/ranking with NEW techniques
        # below the documented top - what they must never do: (1) move an
        # EXISTING technique's order, (2) take the top-1 of a DOCUMENTED
        # corpus target (that verdict belongs to the frozen truth; claiming
        # better on it is a dev-time corpus update, not a runtime pack).
        # selected is a seeded Thompson draw - stochastic by design, so the
        # guard compares the deterministic prior-mean ranking only.
        existing_order = after[:ranking].select { |t| before[:applicable].include?(t) }
        next if existing_order == before[:ranking] && after[:ranking].first == before[:ranking].first

        raise PackError,
          "corpus guard: pack(s) #{packs.map(&:technique).join(", ")} move the verdict " \
          "on #{entry["suite"]}/#{entry["name"]} " \
          "(#{before[:ranking].first} -> #{after[:ranking].first}) - refused"
      end
      packs
    end

    # Pack priors fill the gaps: a taught technique starts on its
    # authored prior, but a base table entry (outcome-adapted or
    # consumer-provided) always wins - the loop stays able to learn.
    def priors_with(packs, base)
      return base if packs.nil? || packs.empty?

      merged = base.transform_values(&:dup)
      packs.each do |pack|
        merged[pack.technique] = pack.priors.dup unless merged.key?(pack.technique)
      end
      merged
    end

    def mcts_model(packs)
      return Mcts::STAGE_MODEL if packs.nil? || packs.empty?

      Mcts.merged_model(packs.map(&:mcts))
    end
  end
end
