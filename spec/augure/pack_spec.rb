# frozen_string_literal: true

require "augure"
require "tmpdir"

def pack_yaml(overrides = {})
  base = {
    "technique" => "ret2csu_v2",
    "author" => "claude-code (session test)",
    "source" => "https://example.com/writeup",
    "rules" => [{
      "id" => "app_ret2csu_v2",
      "head" => %w[applicable ret2csu_v2],
      "conditions" => [["fact", "vuln", "sof"], ["match", "gadget", 0, "csu"], ["fact", "nx", "true"]]
    }],
    "kb" => [{
      "id" => "ret2csu_v2_001", "technique" => "ret2csu_v2",
      "description" => "csu gadget chain", "chain" => %w[csu_popper csu_mov],
      "unlocks" => %w[libc_base], "success_rate" => 0.75
    }],
    "mcts" => {"requires" => [], "provides" => %w[libc_base], "terminal" => false, "success" => 0.7},
    "priors" => [14, 6]
  }
  base.merge(overrides)
end

RSpec.describe Augure::Pack do
  describe ".load_hash" do
    it "loads a complete valid pack" do
      pack = described_class.load_hash(pack_yaml)
      expect(pack.technique).to eq("ret2csu_v2")
      expect(pack.rules.size).to eq(1)
      expect(pack.rules.first.id).to eq(:app_ret2csu_v2)
      expect(pack.rules.first.origin).to eq("ret2csu_v2")
      expect(pack.mcts["provides"]).to eq(%w[libc_base])
      expect(pack.priors).to eq([14, 6])
    end

    it "accepts a file path" do
      path = File.join(Dir.mktmpdir, "pack.yml")
      File.write(path, pack_yaml.to_yaml)
      pack = described_class.load_file(path)
      expect(pack.technique).to eq("ret2csu_v2")
    end

    it "rejects a pack without author or source (provenance is not optional)" do
      expect { described_class.load_hash(pack_yaml("author" => nil)) }
        .to raise_error(Augure::PackError, /author/)
      expect { described_class.load_hash(pack_yaml("source" => nil)) }
        .to raise_error(Augure::PackError, /source/)
    end

    it "exposes an optional build: section (packs teach, the builder follows)" do
      with_build = pack_yaml("build" => {"technique" => "ret2csu_v2",
                                         "layout" => [["padding"], ["qword", "gadget:pop_rdi_ret"], ["qword", "win"]]})
      pack = described_class.load_hash(with_build)
      expect(pack.build["technique"]).to eq("ret2csu_v2")
      expect(pack.build["layout"]).to include(["qword", "win"])
    end

    it "rejects a build: section that mismatches the technique or uses unknown slots (check 8)" do
      bad = pack_yaml("build" => {"technique" => "other_technique",
                                  "layout" => [["padding"]]})
      expect { described_class.load_hash(bad) }
        .to raise_error(Augure::PackError, /build.*technique/)
      bad["build"]["technique"] = "ret2csu_v2"
      bad["build"]["layout"] = [["exec_system", "rm -rf /"]]
      expect { described_class.load_hash(bad) }
        .to raise_error(Augure::PackError, /build.*slot/)
    end

    it "exposes an optional detection: section (the defender side)" do
      watched = pack_yaml("detection" => [
        {"channel" => "wire", "signature" => "cyclic pattern of >= 40 bytes", "note" => "the padding phase"},
        {"channel" => "crash", "signature" => "SIGSEGV with a ret to an unmapped page", "note" => "the strike"}
      ])
      pack = described_class.load_hash(watched)
      expect(pack.detection.size).to eq(2)
      expect(pack.detection.first["channel"]).to eq("wire")
    end

    it "rejects a detection: entry outside the channel vocabulary (check 9)" do
      bad = pack_yaml("detection" => [{"channel" => "psychic", "signature" => "s", "note" => "n"}])
      expect { described_class.load_hash(bad) }
        .to raise_error(Augure::PackError, /detection.*channel/)
      bad["detection"][0] = {"channel" => "wire"} # signature + note mandatory
      expect { described_class.load_hash(bad) }
        .to raise_error(Augure::PackError, /detection.*(signature|note)/)
    end

    it "rejects a match pattern that is not a valid regex (check 7: fail at load)" do
      bad = pack_yaml
      bad["rules"][0]["conditions"][1] = ["match", "gadget", 0, "("]
      expect { described_class.load_hash(bad) }
        .to raise_error(Augure::PackError, /match pattern/)
    end

    it "rejects cmp with a non-integer operand or an unknown operator" do
      bad = pack_yaml
      bad["rules"][0]["conditions"][1] = ["cmp", "glibc_minor", "ge", "26"]
      expect { described_class.load_hash(bad) }
        .to raise_error(Augure::PackError, /cmp operand/)
      bad["rules"][0]["conditions"][1] = ["cmp", "glibc_minor", "gtr", 26]
      expect { described_class.load_hash(bad) }
        .to raise_error(Augure::PackError, /cmp operator/)
    end

    it "rejects unknown condition vocabularies" do
      bad = pack_yaml
      bad["rules"][0]["conditions"][0] = ["eval", "system('rm -rf /')"]
      expect { described_class.load_hash(bad) }
        .to raise_error(Augure::PackError, /condition vocabulary/)
    end

    it "rejects conditions on unknown predicates" do
      bad = pack_yaml
      bad["rules"][0]["conditions"][0] = ["fact", "invented_fact", "x"]
      expect { described_class.load_hash(bad) }
        .to raise_error(Augure::PackError, /unknown predicate/)
    end

    it "rejects not_fact on derived relations (stratification)" do
      bad = pack_yaml
      bad["rules"][0]["conditions"][0] = ["not_fact", "has_reg_control", "true"]
      expect { described_class.load_hash(bad) }
        .to raise_error(Augure::PackError, /stratification/)
    end

    it "rejects not_fact on derived relations even newly invented heads" do
      bad = pack_yaml
      bad["rules"][0]["conditions"][0] = ["not_fact", "some_new_head", "true"]
      expect { described_class.load_hash(bad) }
        .to raise_error(Augure::PackError, /stratification/)
    end

    it "rejects heads that already exist in the built-in table" do
      bad = pack_yaml("technique" => "ret2plt")
      bad["rules"][0]["head"] = %w[applicable ret2plt]
      expect { described_class.load_hash(bad) }
        .to raise_error(Augure::PackError, /built-in technique/)
    end

    it "rejects malformed priors" do
      expect { described_class.load_hash(pack_yaml("priors" => [0])) }
        .to raise_error(Augure::PackError, /priors/)
      expect { described_class.load_hash(pack_yaml("priors" => %w[a b])) }
        .to raise_error(Augure::PackError, /priors/)
    end

    it "rejects a kb entry with an out-of-range success_rate" do
      bad = pack_yaml
      bad["kb"][0]["success_rate"] = 1.5
      expect { described_class.load_hash(bad) }
        .to raise_error(Augure::PackError, /success_rate/)
    end

    it "rejects a technique name with wrong shape" do
      expect { described_class.load_hash(pack_yaml("technique" => "Bad Name!")) }
        .to raise_error(Augure::PackError, /technique name/)
    end
  end

  describe "a full pack works end to end through the pipeline" do
    it "makes the packed technique applicable, ranked and provenanced" do
      pack = described_class.load_hash(pack_yaml)
      facts_text = "vuln(\"sof\").\nnx(\"true\").\ngadget(\"csu_popper\", 1).\n"
      result = Augure::Pipeline.analyze(facts: facts_text, packs: [pack], seed: 42)
      expect(result[:applicable]).to include("ret2csu_v2")
      expect(result[:ranking]).to include("ret2csu_v2")
      prov = result[:explain][:provenance]["ret2csu_v2"].first
      expect(prov[:origin]).to eq("ret2csu_v2")
    end

    it "plans multi-step through packed mcts transitions" do
      pack = described_class.load_hash(pack_yaml)
      pack2 = described_class.load_hash(pack_yaml(
        "technique" => "csu_exploit",
        "rules" => [{
          "id" => "app_csu_exploit", "head" => %w[applicable csu_exploit],
          "conditions" => [["fact", "has_csu_gadget", "true"], ["fact", "libc_present", "true"]]
        }],
        "mcts" => {"requires" => %w[libc_base], "provides" => %w[shell], "terminal" => true, "success" => 0.85}
      ))
      first, path = Augure::Mcts.plan(%w[ret2csu_v2 csu_exploit], iterations: 1500, seed: 42,
        model: Augure::Mcts.merged_model([pack, pack2]))
      expect(first).to eq("ret2csu_v2")
      expect(path).to eq(%w[ret2csu_v2 csu_exploit])
    end
  end

  describe "corpus guard (PackLoader)" do
    it "refuses a pack that moves an existing corpus verdict" do
      hostile = described_class.load_hash(pack_yaml(
        "technique" => "greedy_new_tech",
        "rules" => [{"id" => "app_greedy_new_tech", "head" => %w[applicable greedy_new_tech],
                     "conditions" => [["fact", "vuln", "sof"]]}],
        "priors" => [100, 1]
      ))
      expect { Augure::PackLoader.corpus_guard([hostile]) }
        .to raise_error(Augure::PackError, /corpus guard/)
    end

    it "accepts a pack that leaves every corpus verdict untouched" do
      pack = described_class.load_hash(pack_yaml)
      expect(Augure::PackLoader.corpus_guard([pack])).to eq([pack])
    end
  end
end
