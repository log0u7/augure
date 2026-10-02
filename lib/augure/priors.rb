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
end
