# frozen_string_literal: true

module Augure
  # Monte Carlo Tree Search over the technique-transition graph (article 3:
  # AG -> bandit -> MCTS). Nodes are capability sets, edges are verified
  # techniques, rollouts score the discounted product of success rates. A
  # flat bandit cannot value a leak by what it unlocks; this can.
  class Mcts
    # technique => [requires, provides, terminal, base_success]
    STAGE_MODEL = {
      "fmtstr_leak" => [[], %w[libc_base], false, 0.75],
      "fmtstr_canary" => [[], %w[canary], false, 0.70],
      "ret2plt_leak" => [[], %w[libc_base], false, 0.68],
      "ret2libc" => [%w[libc_base], %w[shell], true, 0.85],
      "rop" => [%w[libc_base], %w[shell], true, 0.75],
      # ROP without a libc leak on a PIE target is unreliable (addresses are
      # guessed). Low success reflects the real-world penalty.
      "rop_nocontext" => [[], %w[shell], true, 0.25],
      "ret2plt" => [[], %w[shell], true, 0.75],
      "shellcode" => [[], %w[shell], true, 0.90],
      "stack_pivot" => [[], %w[pivot], false, 0.60],
      # Pivot-gated variants: the real chain only fits after a pivot,
      # modeling the stack-space constraint.
      "ret2plt_leak_big" => [%w[pivot], %w[libc_base], false, 0.68],
      "ret2libc_big" => [%w[pivot libc_base], %w[shell], true, 0.85],
      # Extended vocabulary: techniques documented by public suites.
      "ret2csu" => [[], %w[libc_base], false, 0.70],
      "dlresolve" => [[], %w[shell], true, 0.55],
      "got_overwrite" => [[], %w[shell], true, 0.65],
      # PinTheft (RDS zerocopy double-free privesc, V12 Security): a
      # DOCUMENTED external chain collapsed to its load-bearing spine.
      "io_uring_register" => [[], %w[iouring], false, 0.90],
      "rds_pin_steal" => [%w[iouring], %w[pin_underflow], false, 0.70],
      "page_free" => [%w[pin_underflow], %w[freed_page], false, 0.75],
      "pagecache_reclaim" => [%w[freed_page], %w[pagecache_ctrl], false, 0.65],
      "io_uring_write" => [%w[pagecache_ctrl iouring], %w[suid_overwrite], false, 0.70],
      "suid_exec" => [%w[suid_overwrite], %w[shell], true, 0.90]
    }.freeze

    DISCOUNT = 0.97
    MAX_DEPTH = 6
    UCB_C = 1.41

    class << self
      def caps
        Set.new.freeze
      end

      def available(caps, allowed, model: STAGE_MODEL)
        model.filter_map do |tech, (req, _, _, _)|
          tech if allowed.include?(tech) && req.all? { |r| caps.include?(r) }
        end
      end

      def transition(caps, tech, model: STAGE_MODEL)
        caps + model.fetch(tech)[1]
      end

      def terminal?(caps, model: STAGE_MODEL)
        caps.include?("shell")
      end

      def stage(tech, model: STAGE_MODEL)
        model.fetch(tech)
      end

      # Built-in stage model + technique-pack transitions (packs only add).
      def merged_model(packs)
        merged = STAGE_MODEL.dup
        Array(packs).each do |pack|
          m = pack.mcts
          merged[pack.technique] = [m["requires"], m["provides"], m["terminal"], m["success"]]
        end
        merged.freeze
      end

      # Random rollout: discounted product of success rates down the path.
      # Reaching shell is necessary but not sufficient: the terminal
      # technique's own success scales the reward.
      def rollout(caps, allowed, depth: 0, rng: Random.new, max_depth: MAX_DEPTH, model: STAGE_MODEL)
        return 1.0 if terminal?(caps)
        return 0.0 if depth >= max_depth

        avail = available(caps, allowed, model: model)
        return 0.0 if avail.empty?

        tech = avail[rand_index(rng, avail.size)]
        success = stage(tech, model: model)[3]
        new_caps = transition(caps, tech, model: model)
        success * (DISCOUNT**depth) * rollout(new_caps, allowed, depth: depth + 1, rng: rng, model: model)
      end

      # MCTS from an empty capability set: best first move + most-visited path.
      def plan(allowed, iterations: 2000, seed: nil, model: STAGE_MODEL)
        rng = seed ? Random.new(seed) : Random.new
        root = Node.new(caps: caps)
        root.untried = available(root.caps, allowed, model: model)

        iterations.times do
          node = root
          # 1. Selection
          while node.untried.empty? && !node.children.empty?
            node = node.children.max_by { |n| n.ucb1(node.visits) }
          end
          # 2. Expansion
          unless node.untried.empty?
            tech = node.untried.pop
            new_caps = transition(node.caps, tech, model: model)
            child = Node.new(caps: new_caps, technique_used: tech, parent: node)
            child.untried = terminal?(new_caps) ? [] : available(new_caps, allowed, model: model)
            node.children << child
            node = child
          end
          # 3. Simulation. An already-terminal expansion node scores its own
          #    technique's success, not a flat 1.0.
          reward = if terminal?(node.caps) && node.technique_used
            stage(node.technique_used, model: model)[3]
          else
            rollout(node.caps, allowed, rng: rng, model: model)
          end
          # 4. Backpropagation
          until node.nil?
            node.visits += 1
            node.value += reward
            node = node.parent
          end
        end

        path = []
        node = root
        until node.children.empty?
          node = node.children.max_by(&:visits)
          path << node.technique_used
          break if terminal?(node.caps, model: model)
        end
        best_first = root.children.max_by(&:visits)&.technique_used
        [best_first, path]
      end

      private

      def rand_index(rng, n)
        (rng.rand * n).to_i.clamp(0, n - 1)
      end
    end

    class Node
      attr_reader :caps, :children
      attr_accessor :technique_used, :parent, :visits, :value, :untried

      def initialize(caps:, technique_used: nil, parent: nil)
        @caps = caps.freeze
        @technique_used = technique_used
        @parent = parent
        @children = []
        @visits = 0
        @value = 0.0
        @untried = []
      end

      def ucb1(parent_visits)
        return Float::INFINITY if visits.zero?

        (value / visits) +
          UCB_C * Math.sqrt(Math.log(parent_visits) / visits)
      end
    end
  end
end
