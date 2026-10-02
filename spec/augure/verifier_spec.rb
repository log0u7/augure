# frozen_string_literal: true

require "augure"
require "tmpdir"

RSpec.describe Augure::Verifier do
  describe "arithmetic fast path (default)" do
    it "verifies the payload fits the buffer" do
      expect(described_class.payload_fits(buffer_size: 256, payload_min: 40)).to eq(:sat)
      expect(described_class.payload_fits(buffer_size: 20, payload_min: 40)).to eq(:unsat)
    end

    it "rejects payloads containing bad bytes" do
      clean = "pop rdi".bytes
      dirty = "pop\x00".bytes
      expect(described_class.bad_bytes?(payload: clean, bad_bytes: [0x00, 0x0a])).to be(false)
      expect(described_class.bad_bytes?(payload: dirty, bad_bytes: [0x00, 0x0a])).to be(true)
    end

    it "checks ROP chain feasibility end to end" do
      ok = described_class.rop_chain_feasible?(
        required_gadgets: %w[pop_rdi_ret ret_align],
        present_gadgets: %w[pop_rdi_ret ret_align syscall],
        payload: [0x41, 0x42],
        bad_bytes: [0x00],
        stack_size: 256
      )
      expect(ok).to be(true)

      missing = described_class.rop_chain_feasible?(
        required_gadgets: %w[pop_rdi_ret pop_rsi_ret],
        present_gadgets: %w[pop_rdi_ret],
        payload: [0x41],
        bad_bytes: [],
        stack_size: 256
      )
      expect(missing).to be(false)
    end

    it "fails when the chain overflows the stack space" do
      expect(described_class.rop_chain_feasible?(
        required_gadgets: %w[pop_rdi_ret],
        present_gadgets: %w[pop_rdi_ret],
        payload: Array.new(300, 0x41),
        bad_bytes: [],
        stack_size: 256
      )).to be(false)
    end
  end

  describe "SMT-LIB emission" do
    it "emits a well-formed payload-fits query" do
      smt = described_class.payload_fits_smtlib(256, 40)
      expect(smt).to include("(declare-const buffer_size Int)")
      expect(smt).to include("(assert (>= buffer_size 40))")
      expect(smt).to include("(check-sat)")
    end
  end

  describe "SmtProcess" do
    let(:stub_solver) do
      path = File.join(Dir.tmpdir, "augure_stub_solver_#{Process.pid}.sh")
      File.write(path, "#!/bin/sh\ncat > /dev/null\necho sat\n")
      File.chmod(0o755, path)
      path
    end

    it "solves via a subprocess and returns the status atom" do
      smt = described_class.payload_fits_smtlib(256, 40)
      expect(Augure::SmtProcess.solve(smt, solver: stub_solver)).to eq(:sat)
    ensure
      File.delete(stub_solver)
    end

    it "returns :unknown when the solver times out" do
      path = File.join(Dir.tmpdir, "augure_slow_solver_#{Process.pid}.sh")
      File.write(path, "#!/bin/sh\nsleep 2\necho sat\n")
      File.chmod(0o755, path)
      smt = described_class.payload_fits_smtlib(256, 40)
      expect(Augure::SmtProcess.solve(smt, solver: path, timeout: 0.2)).to eq(:unknown)
    ensure
      File.delete(path)
    end

    it "returns :unknown on garbage output" do
      stub_path = File.join(Dir.tmpdir, "augure_noisy_#{Process.pid}.sh")
      File.write(stub_path, "#!/bin/sh\ncat > /dev/null\necho pancakes\n")
      File.chmod(0o755, stub_path)
      smt = described_class.payload_fits_smtlib(256, 40)
      expect(Augure::SmtProcess.solve(smt, solver: stub_path)).to eq(:unknown)
    ensure
      File.delete(stub_path)
    end
  end
end
