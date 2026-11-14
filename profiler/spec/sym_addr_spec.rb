# frozen_string_literal: true

require "augure-profiler"
require_relative "support/binary_builder"

# The "announces NOTHING" twins (MR6 eval targets) print no banner and
# leak no address: their stage functions, argument strings and gadgets
# are static, so the symbol table IS the address source. sym_addr is
# that fact: a DEFINED symbol's absolute address in a non-PIE module.
RSpec.describe AugureProfiler::Profiler, "sym_addr facts" do
  it "emits the defined function and data symbols of a non-PIE binary" do
    bin = ProfilerBinaryBuilder.local_symbols
    facts = described_class.new(bin).facts.to_s
    symbol_table = `nm #{bin}`

    %w[vault_arm arg_cmd].each do |name|
      addr = symbol_table[/^([0-9a-f]+) \w #{name}$/, 1].to_i(16)
      expect(facts).to include(%(sym_addr("#{name}", #{addr})))
    end
  end

  it "does not emit an imported symbol: an UNDEF has no address" do
    facts = described_class.new(ProfilerBinaryBuilder.local_symbols).facts.to_s
    expect(facts).not_to match(/sym_addr\("puts"/)
  end

  it "does not emit module-relative addresses from a PIE binary" do
    facts = described_class.new(ProfilerBinaryBuilder.local_symbols_pie).facts.to_s
    expect(facts).not_to match(/sym_addr\("vault_arm"/)
  end

  it "does not emit the static libc symbols of a statically linked binary" do
    facts = described_class.new(ProfilerBinaryBuilder.local_symbols_static).facts.to_s
    expect(facts).not_to match(/sym_addr\(/)
  end
end
