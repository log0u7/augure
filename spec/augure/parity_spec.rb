# frozen_string_literal: true

require "augure"
require "augure/parity"

RSpec.describe Augure::Parity do
  def supported_types
    %w[mov_deref_write xchg_rsp_rax syscall_ret pop_rdi_ret pop_rax_ret
      ret_align csu_popper csu_mov]
  end

  def entry(facts, name = "ret2win")
    {"name" => name, "facts" => facts}
  end

  it "passes when every statically-derivable claim is observed" do
    observed = <<~FACTS
      nx("true").
      pie("false").
      canary("false").
      relro("partial").
      plt("puts").
      plt("read").
      target_function("true").
      gadget("pop_rdi_ret", 4196323).
      gadget("ret_align", 4196100).
    FACTS
    claimed = <<~FACTS
      nx("true").
      pie("false").
      canary("false").
      relro("partial").
      plt("puts").
      plt("read").
      target_function("true").
      gadget("pop_rdi_ret", 4198400).
      gadget("ret_align", 4198400).
    FACTS
    result = described_class.check(observed, entry(claimed), supported_gadget_types: supported_types)
    expect(result).to be_ok
    expect(result.missing).to be_empty
    expect(result.checked).to eq(9)
  end

  it "reports a checksec claim the binary contradicts" do
    observed = "nx(\"true\").\npie(\"true\").\n"
    claimed = "nx(\"true\").\npie(\"false\").\n"
    result = described_class.check(observed, entry(claimed), supported_gadget_types: supported_types)
    expect(result).not_to be_ok
    expect(result.missing).to include(["pie", ["false"]])
  end

  it "reports a claimed plt import the binary lacks" do
    observed = "plt(\"puts\").\n"
    claimed = "plt(\"puts\").\nplt(\"print_file\").\n"
    result = described_class.check(observed, entry(claimed), supported_gadget_types: supported_types)
    expect(result).not_to be_ok
    expect(result.missing).to include(["plt", ["print_file"]])
  end

  it "matches gadgets by type, not address" do
    observed = "gadget(\"pop_rdi_ret\", 1).\n"
    claimed = "gadget(\"pop_rdi_ret\", 999).\n"
    expect(described_class.check(observed, entry(claimed), supported_gadget_types: supported_types)).to be_ok
  end

  it "skips gadget types the profiler cannot see instead of failing" do
    observed = "gadget(\"pop_rdi_ret\", 1).\n"
    claimed = "gadget(\"xor_byte\", 1).\n"
    result = described_class.check(observed, entry(claimed), supported_gadget_types: supported_types)
    expect(result).to be_ok
    expect(result.skipped).to include(["gadget", ["xor_byte", 1]])
  end

  it "requires the unsafe-func hint only when the symbol is really imported" do
    imported = "plt(\"gets\").\nvuln_hint(\"unsafe_func:gets\").\n"
    claimed = "vuln_hint(\"unsafe_func:gets\").\n"
    expect(described_class.check(imported, entry(claimed), supported_gadget_types: supported_types)).to be_ok

    absent = "plt(\"read\").\n"
    result = described_class.check(absent, entry(claimed), supported_gadget_types: supported_types)
    expect(result).to be_ok
    expect(result.skipped).to include(["vuln_hint", ["unsafe_func:gets"]])
  end

  it "skips write-up facts no static analysis can derive" do
    observed = "nx(\"true\").\n"
    claimed = "nx(\"true\").\nlimited_stack(\"true\").\nvuln(\"sof\").\n"
    result = described_class.check(observed, entry(claimed), supported_gadget_types: supported_types)
    expect(result).to be_ok
    expect(result.skipped).to contain_exactly(
      ["limited_stack", ["true"]], ["vuln", ["sof"]]
    )
  end

  it "accepts Facts objects as the observed side" do
    observed = Augure::Facts.parse("nx(\"true\").\n")
    claimed = "nx(\"true\").\n"
    expect(described_class.check(observed, entry(claimed), supported_gadget_types: supported_types)).to be_ok
  end
end
