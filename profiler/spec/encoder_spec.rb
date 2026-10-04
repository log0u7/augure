# frozen_string_literal: true

require "augure-profiler"
require "open3"
require "tmpdir"

RSpec.describe AugureProfiler::Encoder do
  let(:runner) do
    exe = File.join(Dir.mktmpdir, "enc_runner")
    src = File.expand_path("support/sc_runner.c", __dir__)
    _, err, status = Open3.capture3("gcc", "-o", exe, src)
    raise "enc_runner build failed: #{err}" unless status.success?

    exe
  end
  let(:flag) do
    f = File.join(Dir.mktmpdir, "flag")
    File.write(f, "FLAG{orw_works}")
    f
  end
  let(:badchars) { [0x00, 0x41, 0x0a, 0x0d] }
  let(:inner) { AugureProfiler::Shellcode.generate(Metasm::X64, :orw, path: flag) }

  it "the xor encoder crosses the channel and runs" do
    e = described_class.encode(inner, badchars: badchars, arch: :x64)
    expect(e[:bytes].unpack("C*") & badchars).to be_empty
    out, _err, status = Open3.capture3(runner, stdin_data: e[:bytes])
    expect(out).to include("FLAG{orw_works}")
    expect(status.to_s).to match(/exit 0/)
  end

  it "the polymorphic decoder is deterministic per seed and runs" do
    a = described_class.encode_polymorphic(inner, badchars: badchars, rng: Random.new(3), arch: :x64)
    b = described_class.encode_polymorphic(inner, badchars: badchars, rng: Random.new(3), arch: :x64)
    expect(a[:bytes]).to eq(b[:bytes])
    expect(a[:bytes].unpack("C*") & badchars).to be_empty
    out, _err, status = Open3.capture3(runner, stdin_data: a[:bytes])
    expect(out).to include("FLAG{orw_works}")
    expect(status.to_s).to match(/exit 0/)
  end

  it "refuses a payload too wide for the byte-wide constants" do
    wide = "A" * 200
    expect {
      described_class.encode_polymorphic(wide, badchars: badchars, rng: Random.new(1), arch: :x64)
    }.to raise_error(ArgumentError, /exceeds/)
  end
end
