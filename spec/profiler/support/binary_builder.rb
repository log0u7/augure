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

  def run(*cmd)
    out, err, _ = system(*cmd)
    raise "build failed: #{cmd.join(" ")}\n#{err}" unless out
  end
end
