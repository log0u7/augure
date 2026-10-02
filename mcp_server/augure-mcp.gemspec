# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name = "augure-mcp"
  spec.version = "0.1.0"
  spec.authors = ["Gregory Epp"]
  spec.email = ["log0u7@users.noreply.github.com"]
  spec.license = "MIT"

  spec.summary = "Read-only MCP server exposing the augure decision layer to LLM agents."
  spec.description = "Three read-only tools: analyze_target (facts in, decision + " \
                     "provenance out), list_rules, explain_technique. The LLM proposes, " \
                     "augure disposes - the decision layer every security agent can call."
  spec.homepage = "https://github.com/log0u7/augure"
  spec.required_ruby_version = ">= 3.4"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir.glob("lib/**/*.rb")
  spec.bindir = "exe"
  spec.executables = ["augure-mcp"]
  spec.require_paths = ["lib"]

  spec.add_dependency "augure", "~> 0.1"
  spec.add_dependency "mcp", "~> 1.6"
end
