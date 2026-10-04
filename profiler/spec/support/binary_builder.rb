# frozen_string_literal: true

require "open3"
require "tmpdir"

# Compiles a KNOWN-vulnerable binary: unbounded copy without canary,
# crashes (SIGSEGV) when stdin carries a long input. Same pattern as the
# core suite's binary builder.
module ProfilerBinaryBuilder
  module_function

  def vulnerable(dir = Dir.mktmpdir("augure_fuzz"))
    src = File.join(dir, "vuln_input.c")
    File.write(src, <<~C)
      #include <string.h>
      #include <unistd.h>
      __attribute__((noinline)) int vuln_copy(const char *src) {
        char small[8];
        strcpy(small, src); /* the write-up classic: unbounded, counter in libc */
        return small[0];
      }
      int main(void) {
        char big[512];
        ssize_t n = read(0, big, sizeof(big) - 1);
        if (n < 16) return 1;
        big[n] = 0;
        return vuln_copy(big);
      }
    C
    bin = File.join(dir, "vuln_input")
    _out, err, status = Open3.capture3("gcc", src, "-o", bin, "-fno-stack-protector", "-z", "execstack", "-O0")
    raise "build failed: #{err}" unless status.success?

    bin
  end

  def local_system(dir = Dir.mktmpdir("augure_local"))
    # a binary whose ONLY interesting symbol is a LOCAL function named
    # exactly `system`: the ret2plt trap - if the profiler emits
    # plt("system") for a non-import, the decision layer believes a
    # PLT stub exists that does not.
    src = File.join(dir, "local_system.c")
    File.write(src, <<~C)
      __attribute__((noinline)) int system(int a) { return a + 1; }
      int main(void) { return system(41) - 41; }
    C
    bin = File.join(dir, "local_system")
    _out, err, status = Open3.capture3("gcc", src, "-o", bin, "-fno-stack-protector", "-O0")
    raise "build failed: #{err}" unless status.success?

    bin
  end
end
