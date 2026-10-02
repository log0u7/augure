# frozen_string_literal: true

module Augure
  # Thompson-sampling bandit over Beta posteriors. The prior table encodes the
  # AG weight inversions ("humans overweight X, the data says underweight"):
  # ret2plt (15, 5) vs the human prior that anchored on ROP chains.
  class Bandit
    # Beta(alpha, beta) arm. Sampling uses Marsaglia-Tsang gamma draws: if
    # X ~ Gamma(a) and Y ~ Gamma(b) then X / (X + Y) ~ Beta(a, b). Ruby's
    # stdlib has no Beta sampler; this is the standard construction.
    class Arm
      attr_reader :alpha, :beta

      def initialize(alpha, beta, rng: Random.new)
        @alpha = alpha.to_f
        @beta = beta.to_f
        @rng = rng
      end

      def mean
        @alpha / (@alpha + @beta)
      end

      def sample
        x = gamma(@alpha)
        y = gamma(@beta)
        x / (x + y)
      end

      def record(success)
        success ? @alpha += 1 : @beta += 1
      end

      private

      # Marsaglia-Tsang, shape >= 1 handled directly; shape < 1 via the
      # boost transform.
      def gamma(shape)
        if shape < 1.0
          u = non_zero
          gamma(shape + 1.0) * u**(1.0 / shape)
        else
          d = shape - 1.0 / 3.0
          c = 1.0 / Math.sqrt(9.0 * d)
          loop do
            x = gauss
            v = (1.0 + c * x)**3
            next if v <= 0

            u = non_zero
            return d * v if Math.log(u) < 0.5 * x * x + d * (1.0 - v + Math.log(v))
          end
        end
      end

      def non_zero
        u = @rng.rand until u && u > 0.0
        u
      end

      # Box-Muller transform.
      def gauss
        loop do
          u1 = non_zero
          u2 = @rng.rand
          r = Math.sqrt(-2.0 * Math.log(u1))
          theta = 2.0 * Math::PI * u2
          return r * Math.sin(theta)
        end
      end
    end

    attr_reader :arms, :rng, :history

    def initialize(priors: {}, rng: Random.new)
      @rng = rng
      @arms = {}
      priors.each { |tech, (a, b)| @arms[tech] = Arm.new(a, b, rng: @rng) }
      @history = []
    end

    def arm(technique)
      @arms[technique] ||= Arm.new(1, 1, rng: @rng)
    end

    def mean(technique)
      arm(technique).mean
    end

    # Thompson sample, restricted to the verified techniques. Deterministic
    # for a fixed rng seed.
    def select(verified)
      return nil if verified.empty?

      verified.max_by { |t| arm(t).sample }
    end

    def rankings
      @arms.keys.sort_by { |t| [-arm(t).mean, t] }
    end

    def feedback(technique, success)
      arm(technique).record(success)
      @history << {technique: technique, success: success}
      self
    end
  end
end
