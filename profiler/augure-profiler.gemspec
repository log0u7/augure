# frozen_string_literal: true

require_relative "lib/augure-profiler/version"

Gem::Specification.new do |spec|
  spec.name = "augure-profiler"
  spec.version = AugureProfiler::VERSION
  spec.authors = ["Gregory Epp"]
  spec.email = ["log0u7@users.noreply.github.com"]
  spec.license = "MIT"

  spec.summary = "Binary profiler for the augure decision layer: ELF in, Datalog facts out."
  spec.description = "Generates augure fact files from ELF binaries via metasm: checksec " \
                     "protections, PLT imports, unsafe-symbol hints and semantically " \
                     "classified gadgets. The profiler speaks facts; augure decides."
  spec.homepage = "https://github.com/log0u7/augure"
  spec.required_ruby_version = ">= 3.4"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"

  spec.files = Dir.glob(File.expand_path("lib", __dir__) + "/**/*.rb") + [File.expand_path("exe/augure-profile", __dir__)]
  spec.bindir = "exe"
  spec.executables = ["augure-profile"]
  spec.require_paths = ["lib"]

  # metasm is LGPL-2.1, pure Ruby, maintained under jjyg. Isolating it in
  # this gem keeps the augure core at zero runtime dependencies.
  spec.add_dependency "augure", "~> 0.1"
  spec.add_dependency "metasm", "~> 1.0"
end
