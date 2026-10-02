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
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir.glob("lib/**/*.rb") + Dir.glob("lib/**/*.json") + ["LICENSE", "README.md"]
  spec.bindir = "exe"
  spec.executables = ["augure"]
  spec.require_paths = ["lib"]
end
