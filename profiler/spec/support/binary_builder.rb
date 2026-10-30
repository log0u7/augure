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

  # A binary whose .text carries the callme challenge's gadget bytes
  # (pop rsi ; pop r15 ; ret): the pattern the plain pop_rsi scan cannot
  # see. The overlapping pop rdi (5f c3) must survive as its own fact.
  def pop_rsi_r15(dir = Dir.mktmpdir("augure_gad"))
    src = File.join(dir, "gadget.c")
    File.write(src, <<~C)
      __attribute__((noinline, used)) void the_gadget(void) {
        __asm__ volatile(".byte 0x5e,0x41,0x5f,0xc3");
      }
      int main(void) { return 0; }
    C
    bin = File.join(dir, "gadget_bin")
    _out, err, status = Open3.capture3("gcc", src, "-o", bin, "-fno-stack-protector", "-no-pie", "-O0")
    raise "build failed: #{err}" unless status.success?

    bin
  end

  # A binary that IMPORTS a win-named function (the ret2csu shape: the
  # win lives in the companion library). The import is not a win HERE:
  # no win_symbol, no target_function.
  def importing_win(dir = Dir.mktmpdir("augure_win"))
    lib_src = File.join(dir, "libwin.c")
    File.write(lib_src, "void ret2win(void) {}\n")
    lib = File.join(dir, "libwin.so")
    _o, e, s = Open3.capture3("gcc", lib_src, "-shared", "-fPIC", "-o", lib)
    raise "lib build failed: #{e}" unless s.success?

    src = File.join(dir, "importer.c")
    # the volatile global keeps the relocation alive (the compiler
    # cannot fold it away); the function is never called
    File.write(src, <<~C)
      extern void ret2win(void);
      void (*volatile keep)(void) = ret2win;
      int main(void) { return 0; }
    C
    bin = File.join(dir, "importer")
    _o, e, s = Open3.capture3("gcc", src, "-L" + dir, "-lwin", "-o", bin,
      "-fno-stack-protector", "-no-pie", "-O0", "-Wl,-rpath," + dir)
    raise "build failed: #{e}" unless s.success?

    bin
  end

  # A sized copy whose length is an immediate too small to reach the
  # return slot: bounded, not the overflow. -fno-builtin keeps memcpy a
  # real call (the compiler would fold it away otherwise).
  def bounded_memcpy(dir = Dir.mktmpdir("augure_memcpy"))
    src = File.join(dir, "bounded.c")
    File.write(src, <<~C)
      #include <string.h>
      int main(void) {
          char src_buf[16] = "abcdefgh";
          char dst[8];
          memcpy(dst, src_buf, 4);
          return dst[0];
      }
    C
    bin = File.join(dir, "bounded")
    _out, err, status = Open3.capture3("gcc", src, "-o", bin, "-fno-stack-protector", "-no-pie", "-O0", "-fno-builtin")
    raise "build failed: #{err}" unless status.success?

    bin
  end

  # The ret2plt shape: the copy length rides in a register (the read's
  # count), so no immediate bounds the copy: the overflow is real.
  def unbounded_memcpy(dir = Dir.mktmpdir("augure_umemcpy"))
    src = File.join(dir, "unbounded.c")
    File.write(src, <<~C)
      #include <string.h>
      #include <unistd.h>
      __attribute__((noinline)) int vuln_copy(const char *src, long n) {
          char small[8];
          memcpy(small, src, n);
          return (int) n;
      }
      int main(void) {
          char big[512];
          ssize_t n = read(0, big, sizeof(big) - 1);
          if (n < 16) return 1;
          big[n] = 0;
          return vuln_copy(big, n);
      }
    C
    bin = File.join(dir, "unbounded")
    _out, err, status = Open3.capture3("gcc", src, "-o", bin, "-fno-stack-protector", "-no-pie", "-O0", "-fno-builtin")
    raise "build failed: #{err}" unless status.success?

    bin
  end

  # A sized stdin read whose immediate matches the buffer: bounded.
  def bounded_read(dir = Dir.mktmpdir("augure_bread"))
    src = File.join(dir, "bread.c")
    File.write(src, <<~C)
      #include <unistd.h>
      int main(void) {
          char buf[64];
          ssize_t n = read(0, buf, sizeof(buf) - 1);
          return (n > 0) ? buf[0] : 1;
      }
    C
    bin = File.join(dir, "bread")
    _out, err, status = Open3.capture3("gcc", src, "-o", bin, "-fno-stack-protector", "-no-pie", "-O0", "-fno-builtin")
    raise "build failed: #{err}" unless status.success?

    bin
  end

  # printf with a constant format: the classic safe call. -fno-builtin
  # keeps the call (gcc would fold printf("...") to puts otherwise).
  def printf_constant(dir = Dir.mktmpdir("augure_pconst"))
    src = File.join(dir, "pconst.c")
    File.write(src, <<~C)
      #include <stdio.h>
      int main(void) {
          printf("constant format\\n");
          return 0;
      }
    C
    bin = File.join(dir, "pconst")
    _out, err, status = Open3.capture3("gcc", src, "-o", bin, "-fno-stack-protector", "-no-pie", "-O0", "-fno-builtin")
    raise "build failed: #{err}" unless status.success?

    bin
  end

  # The fmtstr shape: the format argument is the attacker's buffer.
  def printf_stack(dir = Dir.mktmpdir("augure_pstack"))
    src = File.join(dir, "pstack.c")
    File.write(src, <<~C)
      #include <stdio.h>
      #include <unistd.h>
      int main(void) {
          char buf[64];
          ssize_t n = read(0, buf, sizeof(buf) - 1);
          if (n < 4) return 1;
          buf[n] = 0;
          printf(buf);
          return 0;
      }
    C
    bin = File.join(dir, "pstack")
    _out, err, status = Open3.capture3("gcc", src, "-o", bin, "-fno-stack-protector", "-no-pie", "-O0", "-fno-builtin")
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
