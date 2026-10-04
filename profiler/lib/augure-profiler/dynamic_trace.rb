# frozen_string_literal: true

require "metasm"
require "open3"
require "tmpdir"

module AugureProfiler
  # The dynamic layer: the debugger in the loop, like the original
  # tool's dbg.pm. Three answers static analysis cannot give:
  #   1. WHICH instruction wrote the overflowing bytes over the return
  #      slot (the taint, proven by a watchpoint on the very address the
  #      static frame read computed);
  #   2. the runtime map (libc, stack, heap) of a live run - the decor
  #      confirmed, not inferred;
  #   3. nothing else - the tests of the built bytes remain the truth.
  module DynamicTrace
    module_function

    # 1. The write-site proof, ONE gdb session (no cross-run address
    # to carry: the stack shifts between runs, the session cannot):
    # break the vulnerable function the static read named, watch the
    # return slot living at $rsp on entry, continue - the stop whose
    # new value carries the input's bytes IS the writing instruction.
    def write_site(binary, input)
      static = StaticOffset.offset(binary)
      return nil unless static&.dig(:function)

      input_file = File.join(Dir.tmpdir, "augure_write_input_#{Process.pid}")
      File.binwrite(input_file, input)
      cmds = [
        "break #{static[:function]}",
        "run < #{input_file}",
        "watch *(unsigned long *) $rsp"
      ]
      6.times { cmds << "continue" }
      cmds << "bt 3" << "x/i $pc"
      out, _err, _st = Open3.capture3({"DEBUGINFOD_URLS" => ""}, "gdb", "-batch",
        *cmds.flat_map { |c| ["-ex", c] }, binary)
      blocks = out.split(/Hardware (?:access |)watchpoint \d+: \*/)
      # the stop whose new value carries our filler bytes (the input's
      # leading word) - the call machinery does not write the pattern
      the_stop = blocks.find { |b| b =~ /New value = 4702111234474983745|New value = 4702111234474983746/ }
      return nil unless the_stop

      new_line = the_stop.lines.index { |l| l.include?("4702111234474983745") }
      pc = new_line ? the_stop.lines[(new_line + 1)..].find { |l| l =~ /0x[0-9a-f]+ in / } : nil
      func = pc&.slice(/in [A-Za-z_@][\w@<>]*/)&.sub("in ", "") || "unknown"
      addr = pc&.slice(/\A\s*0x[0-9a-f]+/)&.strip
      {function: func, instruction: addr.to_s, caller: static[:function], sink: static[:sink]}
    ensure
      File.delete(input_file) if input_file && File.exist?(input_file)
    end

    # 2. The runtime map: what the loader actually mapped for this run.
    # Returns {libc_base:, stack_base:, stack_end:, heap_base:} (nils
    # when absent) - the decor confirmed.
    def runtime_map(binary)
      # at starti the loader has not mapped libc yet: break main, the
      # decor is complete by then
      out, _err, _st = Open3.capture3({"DEBUGINFOD_URLS" => ""}, "gdb", "-batch",
        "-ex", "break main", "-ex", "run", "-ex", "info proc mappings", binary)
      libc_base = nil
      stack_base = nil
      stack_end = nil
      heap_base = nil
      out.lines.each do |l|
        if (m = l.match(/\A\s*(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+\S+\s+\S+\s+(.+?)\s*\z/i))
          lo = m[1].to_i(16)
          hi = m[2].to_i(16)
          what = m[3].to_s.strip
          libc_base ||= lo if /libc\.so/.match?(what)
          stack_base ||= lo if /\[\s*stack\s*\]/i.match?(what)
          stack_end = hi if /\[\s*stack\s*\]/i.match?(what)
          heap_base ||= lo if what.include?("[heap]")
        end
      end
      {libc_base: libc_base, stack_base: stack_base, stack_end: stack_end, heap_base: heap_base}
    end
  end
end
