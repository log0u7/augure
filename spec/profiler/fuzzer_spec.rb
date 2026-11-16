# frozen_string_literal: true

require "spec_helper"
require "augure-profiler/fuzzer"

RSpec.describe AugureProfiler::Fuzzer do
  describe "run" do
    # Every crashing binary costs ~0.5s to a piped systemd-coredump:
    # a full sweep would add minutes to every build. The spawn must
    # clamp RLIMIT_CORE so the kernel skips the coredump helper.
    it "spawns the target with a clamped core limit" do
      fake_status = instance_double(Process::Status, signaled?: false, exitstatus: 0)
      allow(Open3).to receive(:capture3).and_return(["", "", fake_status])

      described_class.run("/bin/true", inputs: 1, max_len: 8)

      expect(Open3).to have_received(:capture3).with(
        "/bin/true", stdin_data: String, rlimit_core: 1
      ).at_least(:once)
    end
  end
end
