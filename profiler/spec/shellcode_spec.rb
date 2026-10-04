# frozen_string_literal: true

require "metasm"
require "augure-profiler/shellcode"
require_relative "support/binary_builder"
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
    %i[sh bash].each do |stub_name|
      %i[x64 x86].each do |arch|
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

RSpec.describe "AugureProfiler.arch" do
  it "reads the ELF class of a target" do
    dir = ProfilerBinaryBuilder.vulnerable
    expect(AugureProfiler.arch(dir)).to eq(:x64)
  end
end

RSpec.describe "the ghost-writing variants" do
  let(:runner) do
    exe = File.join(Dir.mktmpdir, "sc_runner2")
    src = File.expand_path("support/sc_runner.c", __dir__)
    _, err, status = Open3.capture3("gcc", "-o", exe, src)
    raise "sc_runner build failed: #{err}" unless status.success?

    exe
  end

  it "every seed picks an equivalent stub that actually runs" do
    [1, 2, 3, 4, 5].each do |seed|
      stub = AugureProfiler::Shellcode.generate(Metasm::X64, :sh, rng: Random.new(seed))
      out, err, status = Open3.capture3(runner, stdin_data: stub + "exit\n")
      expect(status.success?).to be(true), "seed #{seed} crashed: #{err[0, 120]}"
      expect(out + err).not_to match(/Segmentation|erreur de segmentation/i)
    end
  end

  it "is deterministic per seed" do
    a = AugureProfiler::Shellcode.generate(Metasm::X64, :sh, rng: Random.new(7))
    b = AugureProfiler::Shellcode.generate(Metasm::X64, :sh, rng: Random.new(7))
    expect(a).to eq(b)
  end

  it "x86 seeds assemble valid 32-bit code, deterministic per seed" do
    # the live-run proof needs a 32-bit runner (gcc -m32, multilib);
    # without it the 64-bit runner cannot execute 32-bit stubs (the
    # pop truncates the stack pointer) - so the x86 proof is: the
    # polymorph does not crash, the bytes decode, the seed replays.
    forms = (1..5).map { |seed| AugureProfiler::Shellcode.generate(Metasm::Ia32, :sh, rng: Random.new(seed)) }
    again = (1..5).map { |seed| AugureProfiler::Shellcode.generate(Metasm::Ia32, :sh, rng: Random.new(seed)) }
    expect(forms).to eq(again)
    forms.each do |bytes|
      expect(bytes).to include("\xcd\x80".b)
      di = Metasm::Ia32.new.decode_instruction(Metasm::EncodedData.new(bytes), 0)
      expect(di).not_to be_nil
    end
  end

  it "x86 orw polymorphs without crashing" do
    flag = File.join(Dir.mktmpdir, "flag")
    File.write(flag, "FLAG{x86_polymorph}")
    stub = AugureProfiler::Shellcode.generate(Metasm::Ia32, :orw, path: flag, rng: Random.new(3))
    expect(stub).to include("\xcd\x80".b)
    expect(stub.bytesize).to be < 200
  end
end

RSpec.describe "the parametrized stubs" do
  let(:runner) do
    exe = File.join(Dir.mktmpdir, "sc_runner3")
    src = File.expand_path("support/sc_runner.c", __dir__)
    _, err, status = Open3.capture3("gcc", "-o", exe, src)
    raise "sc_runner build failed: #{err}" unless status.success?

    exe
  end

  it "assembles an orw stub that reads and prints the flag file" do
    flag = File.join(Dir.mktmpdir, "flag")
    File.write(flag, "FLAG{orw_works}")
    stub = AugureProfiler::Shellcode.generate(Metasm::X64, :orw, path: flag)
    out, _err, status = Open3.capture3(runner, stdin_data: stub + "\nexit\n")
    expect(out).to include("FLAG{orw_works}")
    expect(status.success?).to be(true)
  end

  it "refuses a path-bearing stub assembled without its path" do
    expect do
      AugureProfiler::Shellcode.generate(Metasm::X64, :orw)
    end.to raise_error(ArgumentError, /path/)
  end
end

RSpec.describe "the ghost-writing pools" do
  let(:runner) do
    exe = File.join(Dir.mktmpdir, "sc_runner4")
    src = File.expand_path("support/sc_runner.c", __dir__)
    _, err, status = Open3.capture3("gcc", "-o", exe, src)
    raise "sc_runner build failed: #{err}" unless status.success?

    exe
  end

  it "ten seeds, ten living stubs, deterministic per seed" do
    forms = (1..10).map { |seed| AugureProfiler::Shellcode.generate(Metasm::X64, :sh, rng: Random.new(seed)) }
    again = (1..10).map { |seed| AugureProfiler::Shellcode.generate(Metasm::X64, :sh, rng: Random.new(seed)) }
    expect(forms).to eq(again) # the audit reproduces the exact payload
    forms.each_with_index do |stub, i|
      _out, err, status = Open3.capture3(runner, stdin_data: stub + "\nexit\n")
      expect(status.to_s).to match(/exit 0/), "seed #{i + 1} died: #{err[0, 100]}"
    end
  end
end
