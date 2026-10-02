# frozen_string_literal: true

require "open3"
require "timeout"

module Augure
  # Thin subprocess boundary to any SMT-LIB solver (z3, bitwuzla, cvc5).
  # Contract: SMT-LIB text in, status atom out. Unknown/timeout = :unknown,
  # never an exception: a verification failure must be visible, not fatal.
  module SmtProcess
    module_function

    def solve(smt_text, solver:, timeout: 10)
      out = nil
      ok = false
      Open3.popen3(solver) do |stdin, stdout, _stderr, waiter|
        stdin.write(smt_text)
        stdin.close
        begin
          Timeout.timeout(timeout) do
            out = stdout.read
            ok = waiter.value.success?
          end
        rescue Timeout::Error
          kill_quietly(waiter)
          return :unknown
        end
      end
      parse_status(out) if ok
    rescue
      :unknown
    end

    def parse_status(stdout)
      case stdout
      when /\bsat\b/ then :sat
      when /\bunsat\b/ then :unsat
      else :unknown
      end
    end

    def kill_quietly(waiter)
      Process.kill("KILL", waiter.pid)
    rescue
      nil
    end
  end
end
