# frozen_string_literal: true

require "open3"
require "timeout"

module Augure
  # Numerical feasibility checks. The fast path is constant arithmetic in
  # plain Ruby; the same checks emit SMT-LIB v2 text for a real solver via
  # SmtProcess. The formal story survives because both paths run on the same
  # corpus and must agree.
  module Verifier
    module_function

    def payload_fits(buffer_size:, payload_min:)
      (buffer_size >= payload_min) ? :sat : :unsat
    end

    def bad_bytes?(payload:, bad_bytes:)
      payload.any? { |byte| bad_bytes.include?(byte) }
    end

    def rop_chain_feasible?(required_gadgets:, present_gadgets:, payload:, bad_bytes:, stack_size:)
      return false unless (required_gadgets - present_gadgets).empty?
      return false if bad_bytes?(payload: payload, bad_bytes: bad_bytes)
      return false if payload.size > stack_size

      true
    end

    def payload_fits_smtlib(buffer_size, payload_min)
      <<~SMT
        (set-logic QF_LIA)
        (declare-const buffer_size Int)
        (assert (= buffer_size #{buffer_size.to_i}))
        (assert (>= buffer_size #{payload_min.to_i}))
        (check-sat)
      SMT
    end
  end
end
