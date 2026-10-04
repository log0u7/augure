# frozen_string_literal: true

require_relative "lib/augure/version"

Gem::Specification.new do |spec|
  spec.name = "augure"
  spec.version = Augure::VERSION
  spec.authors = ["Gregory Epp"]
  spec.email = ["log0u7@users.noreply.github.com"]
  spec.license = "MIT"

  spec.summary = "Auditable exploitation decision layer: propose, verify, explain."
  spec.description = "Augure encodes exploitation technique selection as Datalog rules " \
                     "verified by arithmetic and SMT checks, ranked by Beta-bandit priors " \
                     "and planned by MCTS. Every decision is reproducible and explainable. " \
                     "Augure decides. It never executes."
  spec.homepage = "https://github.com/log0u7/augure"
  spec.required_ruby_version = ">= 3.4"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"

  spec.files = Dir.glob(File.expand_path("lib", __dir__) + "/**/*.rb") + Dir.glob(File.expand_path("lib", __dir__) + "/**/*.json") + Dir.glob(File.expand_path("packs", __dir__) + "/*.yml") + Dir.glob(File.expand_path("examples", __dir__) + "/*.facts") + Dir.glob(File.expand_path("docs", __dir__) + "**/*.md") + ["LICENSE", "README.md", "CHANGELOG.md"] + [File.expand_path("exe/augure", __dir__), File.expand_path("exe/augure-benchmark", __dir__)]
  spec.bindir = "exe"
  spec.executables = %w[augure augure-benchmark]
  spec.require_paths = ["lib"]
end
