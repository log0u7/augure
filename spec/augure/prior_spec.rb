# frozen_string_literal: true

require "augure"
require "augure/pack_loader"

RSpec.describe Augure::Pipeline do
  describe ".default_priors" do
    it "gives ret2libc a mean above ret2vdso (it wins the competition on classic targets)" do
      priors = described_class.default_priors
      alpha, beta = priors["ret2libc"]
      mean = alpha / (alpha + beta).to_f
      expect(mean).to be > 0.25, "ret2libc prior mean is #{mean} (alpha=#{alpha}, beta=#{beta})"
    end

    it "keeps ret2vdso below shellcode/ret2plt so it does not steal wins" do
      priors = described_class.default_priors
      pack_path = File.join(__dir__, "../../packs/ret2vdso.yml")
      pack = Augure::PackLoader.load_file(pack_path)
      merged = Augure::PackLoader.priors_with([pack], priors)
      alpha, beta = merged["ret2vdso"]
      mean = alpha / (alpha + beta).to_f
      expect(mean).to be < 0.3, "ret2vdso prior mean is #{mean} (alpha=#{alpha}, beta=#{beta})"
    end
  end

  describe ".analyze with ret2libc vs ret2vdso competition" do
    let(:ret2libc_facts) do
      # classic ret2libc target: PIE + NX + puts@plt leak, no syscall gadget in vDSO reach
      "nx(\"true\").\npie(\"true\").\ncanary(\"false\").\nvuln(\"sof\").\nplt(\"puts\").\nplt(\"__libc_start_main\").\n"
    end

    it "selects ret2libc over ret2vdso on a classic ret2libc target (deterministic seed)" do
      wins = {"ret2libc" => 0, "ret2vdso" => 0, "other" => 0}
      200.times do |i|
        result = described_class.analyze(facts: ret2libc_facts, seed: 1000 + i)
        selected = result[:selected]
        wins["ret2libc"] += 1 if selected == "ret2libc"
        wins["ret2vdso"] += 1 if selected == "ret2vdso"
        wins["other"] += 1 unless %w[ret2libc ret2vdso].include?(selected)
      end
      expect(wins["ret2libc"]).to be > wins["ret2vdso"],
        "ret2libc won #{wins["ret2libc"]}/200, ret2vdso won #{wins["ret2vdso"]}/200"
    end
  end
end
