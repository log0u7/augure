# frozen_string_literal: true

module Augure
  # AG-derived priors (200 synthetic targets, seed 42) encoding the weight
  # inversions the genetic algorithm found against human intuition:
  # humans overweighted shellcode/ret2libc and underweighted ret2plt/fmtstr.
  AG_PRIORS = {
    "shellcode" => [5, 13],
    "ret2libc" => [2, 18],
    "rop" => [10, 10],
    "fmtstr_write" => [12, 8],
    "ret2plt" => [15, 5],
    "ret2func" => [16, 4],
    "srop" => [4, 6],
    "dlresolve" => [3, 7],
    "heap_fastbin" => [3, 7],
    "heap_tcache" => [4, 6],
    "heap_overwrite" => [12, 8],
    "ret2plt_leak" => [8, 4]
  }.freeze

  # Priors for techniques the AG simulation did not cover. Authored from
  # documented public suites (ROP Emporium, Protostar, exploit.education
  # Phoenix write-ups) and calibrated with KB pseudo-counts - declared as
  # authored constants, not as measured results.
  EXTENDED_PRIORS = {
    "fmtstr_leak" => [13, 7],   # leaks are enablers: they defeat PIE/canary
    "ret2csu" => [14, 6],       # reliable when the csu gadgets exist
    "stack_pivot" => [13, 7],   # required under stack-space constraints
    "got_overwrite" => [13, 7]  # partial RELRO makes GOT redirection cheap
  }.freeze
end
