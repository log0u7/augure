# frozen_string_literal: true

module Augure
  # Rules-as-data: the single source of truth for technique applicability.
  #
  # Each rule is data: an id (the provenance handle), a head relation/value,
  # and a list of conditions. The Engine interprets the table; a future
  # generator emits the same table as a Souffle .dl program, so the two
  # engines cannot diverge the way the Python prototype's did.
  #
  # Condition forms:
  #   [:fact,     rel, val]            any tuple rel(val) present
  #   [:not_fact, rel, val]            rel(val) absent (inputs only)
  #   [:match,    rel, idx, pattern]   arg idx matches /pattern/
  #   [:cmp,      rel, op, n]          integer arg satisfies V <op> n
  class Rules
    Rule = Struct.new(:id, :head, :conditions, :source, :origin)

    APPLICABLE = "applicable"

    # Input-relation defaults, matching the prototype's closed-world
    # semantics: an absent fact means the default below, not absence.
    DEFAULTS = {
      "nx" => "true", "pie" => "true", "canary" => "false"
    }.freeze

    class << self
      def all
        @all ||= build.freeze
      end

      def applicable_rules
        all.select { |r| r.head[0] == APPLICABLE }
      end

      def inputs
        Facts::SCHEMA
      end

      private

      def build
        builder = Builder.new
        builder.tap { |b| populate(b) }.rules
      end

      def populate(b)
        # -- derived: vulnerability classes from hints -------------------
        b.rule :vuln_sof_gets, %w[vuln sof],
          source: "gets() presence implies stack overflow" do |c|
          c.match "vuln_hint", 0, "unsafe_func:gets"
        end
        b.rule :vuln_sof_strcpy, %w[vuln sof],
          source: "strcpy() presence implies stack overflow" do |c|
          c.match "vuln_hint", 0, "unsafe_func:strcpy"
        end
        b.rule :vuln_fmtstr_printlike, %w[vuln fmtstr],
          source: "printf-like unsized format functions" do |c|
          c.match "vuln_hint", 0, "printf|sprintf"
        end

        # -- derived: gadget families ------------------------------------
        b.rule :fam_reg_control, %w[has_reg_control true],
          source: "any pop gadget gives register control" do |c|
          c.match "gadget", 0, "pop"
        end
        b.rule :fam_write_primitive, %w[has_write_primitive true],
          source: "any mov-store gadget gives a write primitive" do |c|
          c.match "gadget", 0, "mov"
        end
        b.rule :fam_syscall_gadget, %w[has_syscall_gadget true],
          source: "syscall or int80 gadget" do |c|
          c.match "gadget", 0, "syscall|int80"
        end
        b.rule :fam_csu_gadget, %w[has_csu_gadget true],
          source: "__libc_csu_init popper/mov gadget family" do |c|
          c.match "gadget", 0, "csu"
        end
        b.rule :fam_pivot_gadget, %w[has_pivot_gadget true],
          source: "stack pivot gadget (xchg/mov rsp)" do |c|
          c.match "gadget", 0, "xchg"
        end
        b.rule :enough_from_reg, %w[enough_gadgets true],
          source: "register control alone sustains a ROP chain" do |c|
          c.fact "has_reg_control", "true"
        end
        b.rule :enough_from_write, %w[enough_gadgets true],
          source: "a write primitive alone sustains a ROP chain" do |c|
          c.fact "has_write_primitive", "true"
        end

        # -- applicable: stack techniques (vuln = sof) --------------------
        b.rule :app_shellcode, ["applicable", "shellcode"],
          source: "NX off + no canary + unfiltered return: inject and jump" do |c|
          c.fact "vuln", "sof"
          c.fact "nx", "false"
          c.fact "canary", "false"
          c.not_fact "return_addr_filtered", "true"
        end
        b.rule :app_ret2func, ["applicable", "ret2func"],
          source: "win function present at fixed address, no PIE" do |c|
          c.fact "vuln", "sof"
          c.fact "pie", "false"
          c.fact "target_function", "true"
        end
        b.rule :app_ret2plt, ["applicable", "ret2plt"],
          source: "system@plt imported: call it directly, no leak" do |c|
          c.fact "vuln", "sof"
          c.fact "nx", "true"
          c.fact "pie", "false"
          c.fact "plt", "system"
        end
        b.rule :app_ret2libc_plt, ["applicable", "ret2libc"],
          source: "__libc_start_main@plt exposes libc base" do |c|
          c.fact "vuln", "sof"
          c.fact "plt", "__libc_start_main"
        end
        b.rule :app_ret2libc_libc, ["applicable", "ret2libc"],
          source: "libc known/version pinned: offsets computable" do |c|
          c.fact "vuln", "sof"
          c.fact "libc_present", "true"
        end
        b.rule :app_rop, ["applicable", "rop"],
          source: "NX on with gadget supply: chain primitives" do |c|
          c.fact "vuln", "sof"
          c.fact "nx", "true"
          c.fact "enough_gadgets", "true"
        end
        b.rule :app_srop, ["applicable", "srop"],
          source: "sigreturn frame + syscall gadget: full register set" do |c|
          c.fact "vuln", "sof"
          c.fact "sigreturn_frame", "true"
          c.fact "has_syscall_gadget", "true"
        end
        b.rule :app_ret2plt_leak, ["applicable", "ret2plt_leak"],
          source: "PIE on: leak via puts@plt with register control" do |c|
          c.fact "vuln", "sof"
          c.fact "nx", "true"
          c.fact "pie", "true"
          c.fact "plt", "puts"
          c.fact "has_reg_control", "true"
        end

        # -- applicable: format string -----------------------------------
        b.rule :app_fmtstr_write, ["applicable", "fmtstr_write"],
          source: "format string bug: arbitrary write, NX-independent" do |c|
          c.fact "vuln", "fmtstr"
        end
        # The leak is a strategy of its own when there is a read primitive or
        # a protection worth bypassing: %x/%s reads defeat PIE and canaries.
        b.rule :app_fmtstr_leak_read, ["applicable", "fmtstr_leak"],
          source: "read primitive: arbitrary stack read via format string" do |c|
          c.fact "vuln", "fmtstr"
          c.fact "fmtstr_read", "true"
        end
        b.rule :app_fmtstr_leak_pie, ["applicable", "fmtstr_leak"],
          source: "PIE on: leak a code pointer to defeat ASLR" do |c|
          c.fact "vuln", "fmtstr"
          c.fact "pie", "true"
        end
        b.rule :app_fmtstr_leak_canary, ["applicable", "fmtstr_leak"],
          source: "canary on: leak the stack cookie before smashing" do |c|
          c.fact "vuln", "fmtstr"
          c.fact "canary", "true"
        end

        # -- applicable: deferred symbol resolution ----------------------
        b.rule :app_ret2dlresolve, ["applicable", "ret2dlresolve"],
          source: "lazy binding + writable relocation: fake DT_SYMTAB " \
                  "resolves an arbitrary symbol (ROP Emporium " \
                  "ret2dlresolve, documented)" do |c|
          c.fact "vuln", "sof"
          c.fact "nx", "true"
          c.fact "pie", "false"
          c.fact "dt_lazy", "true"
          c.fact "reloc_writable", "true"
        end

        # -- applicable: __libc_csu_init gadget universe -----------------
        b.rule :app_ret2csu, ["applicable", "ret2csu"],
          source: "csu gadgets populate rdx/rsi/rdi in sparse binaries " \
                  "(ROP Emporium ret2csu, documented)" do |c|
          c.fact "vuln", "sof"
          c.fact "nx", "true"
          c.fact "has_csu_gadget", "true"
        end

        # -- applicable: stack pivot under space constraints --------------
        b.rule :app_stack_pivot, ["applicable", "stack_pivot"],
          source: "limited stack space: pivot to a larger buffer first " \
                  "(ROP Emporium pivot, documented)" do |c|
          c.fact "vuln", "sof"
          c.fact "nx", "true"
          c.fact "limited_stack", "true"
          c.fact "has_pivot_gadget", "true"
        end

        # -- applicable: GOT overwrite ------------------------------------
        b.rule :app_got_overwrite_sof, ["applicable", "got_overwrite"],
          source: "writable GOT target: overwrite an entry to redirect " \
                  "a call via a ROP write primitive (documented)" do |c|
          c.fact "vuln", "sof"
          c.fact "nx", "true"
          c.fact "got_overwrite_target", "true"
          c.not_fact "relro", "full"
        end
        b.rule :app_got_overwrite_fmtstr, ["applicable", "got_overwrite"],
          source: "writable GOT + format string: %n writes the GOT " \
                  "entry and redirects the call (phoenix format-four, " \
                  "documented)" do |c|
          c.fact "vuln", "fmtstr"
          c.fact "got_overwrite_target", "true"
          c.not_fact "relro", "full"
        end

        # -- applicable: heap ---------------------------------------------
        b.rule :app_heap_tcache_alloc, ["applicable", "heap_tcache"],
          source: "tcache allocator: tcache poisoning" do |c|
          c.fact "vuln", "heap"
          c.fact "allocator", "tcache"
        end
        b.rule :app_heap_tcache_glibc, ["applicable", "heap_tcache"],
          source: "glibc 2.26..2.33: tcache exists by default" do |c|
          c.fact "vuln", "heap"
          c.cmp "glibc_minor", :ge, 26
          c.cmp "glibc_minor", :lt, 34
        end
        b.rule :app_heap_fastbin_glibc, ["applicable", "heap_fastbin"],
          source: "glibc < 2.26: fastbin is the mechanism" do |c|
          c.fact "vuln", "heap"
          c.cmp "glibc_minor", :lt, 26
        end
        b.rule :app_heap_fastbin_alloc, ["applicable", "heap_fastbin"],
          source: "ptmalloc2 fastbin context" do |c|
          c.fact "vuln", "heap"
          c.fact "allocator", "ptmalloc2"
        end
        b.rule :app_heap_overwrite_dlmalloc, ["applicable", "heap_overwrite"],
          source: "dlmalloc: adjacency overwrite" do |c|
          c.fact "vuln", "heap"
          c.fact "allocator", "dlmalloc"
        end
        b.rule :app_heap_overwrite_fp, ["applicable", "heap_overwrite"],
          source: "function pointer on heap: overwrite it" do |c|
          c.fact "vuln", "heap"
          c.fact "function_pointer_on_heap", "true"
        end
      end
    end

    # Tiny DSL used to declare rules as data.
    class Builder
      attr_reader :rules

      def initialize
        @rules = []
      end

      def rule(id, head, source:, &block)
        collector = ConditionCollector.new
        block.call(collector)
        @rules << Rule.new(
          id: id, head: head, conditions: collector.conditions, source: source
        )
      end

      class ConditionCollector
        attr_reader :conditions

        def initialize
          @conditions = []
        end

        def fact(rel, val)
          @conditions << [:fact, rel, val]
        end

        def not_fact(rel, val)
          @conditions << [:not_fact, rel, val]
        end

        def match(rel, idx, pattern)
          @conditions << [:match, rel, idx, pattern]
        end

        def cmp(rel, op, n)
          @conditions << [:cmp, rel, op, n]
        end
      end
    end
  end
end
