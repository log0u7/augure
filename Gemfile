# frozen_string_literal: true

source "https://rubygems.org"

gemspec

gemspec path: "profiler", name: "augure-profiler"

gemspec path: "mcp_server", name: "augure-mcp"

group :development, :test do
  gem "irb" # bin/console (no longer a default gem from Ruby 4.0)
  gem "rspec", "~> 3.13"
  gem "standard", "~> 1.56"
  gem "bundler-audit", "~> 0.9"
end
