# frozen_string_literal: true

# Builds tiny test binaries with KNOWN protections (gcc flags decide the
# facts). Built once per spec run into a tmpdir; CI (ubuntu) ships gcc.

require "tmpdir"

module BinaryBuilder
  module_function

  def build(dir = Dir.mktmpdir("augure_profiler_test"))
    c = File.join(dir, "vuln.c")
    File.write(c, <<~C)
      #include <string.h>
      #include <unistd.h>
      extern char *gets(char *);
      int main(void) { char buf[64]; gets(buf); return 0; }
    C
    # NX off (execstack), PIE off, no canary, default partial RELRO
    gcc(dir, c, "vuln_nx_off_nopie",
      "-fno-stack-protector", "-no-pie", "-z", "execstack")
    # Hardened: PIE, canary, full RELRO (nx on by default)
    gcc(dir, c, "hardened_full_relro",
      "-fstack-protector-all", "-Wl,-z,relro,-z", "now")
    dir
  end

  def gadget_binary(dir)
    src = File.join(dir, "gadgets.s")
    File.write(src, <<~ASM)
      .global _start
      .text
      _start:
        nop
        pop %rdi
        ret
        nop
        pop %rax
        ret
        nop
        xchg %rax, %rsp
        ret
        nop
        mov %rdi, (%rax)
        ret
        nop
        mov %r15, (%r14)
        ret
        nop
        jmp %rsp
        ret
        nop
        syscall
        ret
        nop
        ret
        nop
    ASM
    obj = File.join(dir, "gadgets.o")
    bin = File.join(dir, "gadget_binary")
    run("gcc", "-c", src, "-o", obj)
    run("ld", obj, "-o", bin, "-e", "_start", "--entry=_start")
    bin
  end

  def gcc(dir, source, name, *flags)
    out = File.join(dir, name)
    run("gcc", source, "-o", out, *flags)
    out
  end

  # The static-pie twins (the lab's ret2partial_overwrite shape): the
  # libc is EMBEDDED (no PLT stubs, the unsafe calls go straight to
  # the defined symbols) and the canary symbol rides along unused
  # when the stack protector is off. The vulnerable twin: read into a
  # 64-byte stack buffer with a 256-byte count.
  def static_pie(dir = Dir.mktmpdir("augure_static_pie"))
    src = File.join(dir, "static_pie.c")
    File.write(src, <<~C)
      #include <unistd.h>
      #include <fcntl.h>
      __attribute__((noinline)) void win(void) {
          int fd = open("/dev/null", O_RDONLY);
          if (fd >= 0) close(fd);
          _exit(0);
      }
      __attribute__((noinline)) int vuln(void) {
          char buf[64];
          return (int) read(0, buf, 256);
      }
      int main(void) { vuln(); return 0; }
    C
    gcc(dir, src, "static_pie_nocanary", "-fno-stack-protector", "-static-pie", "-O0")
    gcc(dir, src, "static_pie_canary", "-fstack-protector-strong", "-static-pie", "-O0")
    dir
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
    gcc(dir, src, "local_system", "-fno-stack-protector", "-O0")
  end

  def run(*cmd)
    out, err, = system(*cmd)
    raise "build failed: #{cmd.join(" ")}\n#{err}" unless out
  end
end
