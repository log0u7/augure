# frozen_string_literal: true

require "metasm"
require "augure-profiler/shellcode"
require "open3"
require "tmpdir"

RSpec.describe AugureProfiler::Shellcode do
  let(:runner) do
    exe = File.join(Dir.mktmpdir, "sc_runner")
    src = File.expand_path("support/sc_runner.c", __dir__)
    _, err, status = Open3.capture3("gcc", "-o", exe, src)
    raise "sc_runner build failed: #{err}" unless status.success?

    exe
  end

  # The real regression test: execute the assembled stub. These are our
  # own bytes (trusted); the shell spawns /bin/sh and we feed it exit.
  # Catches the entire class of broken-stub bugs (stack-abuse over the
  # argv array, relocation garbage) that byte-count assertions miss.
  it "assembles an x64 execve /bin/sh stub that actually runs" do
    stub = described_class.generate(Metasm::X64, :sh)
    out, err, status = Open3.capture3(runner, stdin_data: stub + "exit\n")
    expect(status.success?).to be(true), "stub crashed: #{err[0, 120]}"
    expect(out + err).not_to match(/Segmentation|erreur de segmentation/i)
  end

  it "assembles an x64 bash -p stub that actually runs" do
    stub = described_class.generate(Metasm::X64, :bash)
    out, err, status = Open3.capture3(runner, stdin_data: stub + "exit\n")
    expect(status.success?).to be(true), "stub crashed: #{err[0, 120]}"
    expect(out + err).not_to match(/Segmentation|erreur de segmentation/i)
  end

  it "assembles the x86 stubs with the int80 marker" do
    expect(described_class.generate(Metasm::Ia32, :sh)).to include("\xcd\x80".b)
    expect(described_class.generate(Metasm::Ia32, :bash)).to include("\xcd\x80".b)
  end

  it "carries the call-back layout: the stub pops the path address it pushed" do
    [:sh, :bash].each do |stub_name|
      [:x64, :x86].each do |arch|
        bytes = described_class.generate((arch == :x64) ? Metasm::X64 : Metasm::Ia32, stub_name)
        expect(bytes.bytes.first).to eq(0xE8), "#{stub_name}_#{arch} must start with call (e8), not jmp"
      end
    end
  end

  it "is deterministic - same source, same bytes" do
    a = described_class.generate(Metasm::X64, :sh)
    b = described_class.generate(Metasm::X64, :sh)
    expect(a).to eq(b)
  end
end
