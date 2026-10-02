# frozen_string_literal: true

require "json"

module Augure
  # Retrieval-augmented knowledge base over a seed corpus of documented
  # exploitation patterns (ROP Emporium / Protostar / pwnable.tw write-ups).
  # Pure-Ruby TF-IDF; a consumer can swap in an embedding endpoint, the
  # interface stays query -> ranked entries.
  class KnowledgeBase
    CORPUS_PATH = File.join(__dir__, "kb_corpus.json")
    PSEUDO_COUNTS = 10
    MIN_SCORE = 0.05

    Entry = Struct.new(:doc, :score)

    def self.corpus
      @corpus ||= JSON.parse(File.read(CORPUS_PATH)).freeze
    end

    def self.priors
      accum = Hash.new { |h, k| h[k] = [0.0, 0.0] }
      corpus.each do |entry|
        tech = entry["technique"]
        rate = entry["success_rate"]
        next if !tech || rate.nil?

        accum[tech][0] += rate * PSEUDO_COUNTS
        accum[tech][1] += (1 - rate) * PSEUDO_COUNTS
      end
      accum
    end

    def self.transitions
      corpus.each_with_object(Hash.new { |h, k| h[k] = [] }) do |entry, acc|
        unlocks = entry["unlocks"]
        next if !entry["technique"] || !unlocks.is_a?(Array)

        unlocks.each { |u| acc[entry["technique"]] << u unless acc[entry["technique"]].include?(u) }
      end
    end

    attr_reader :size

    def initialize
      @corpus = self.class.corpus
      @size = @corpus.size
      build_index
    end

    def query(text, technique: nil, n_results: 3)
      candidates = @corpus.each_with_index.select { |e, _| technique.nil? || e["technique"] == technique }
      candidates = @corpus.each_with_index.to_a if candidates.empty?
      return [] if candidates.empty?

      q = encode(text)
      scored = candidates.filter_map do |entry, i|
        score = dot(@vectors[i], q)
        Entry.new(entry, score) if score >= MIN_SCORE
      end
      scored.sort_by { |e| -e.score }.first(n_results)
    end

    private

    def build_index
      texts = @corpus.map { |e| e["description"] }
      tokens = texts.map { |t| tokenize(t) }
      @vocab = {}
      tokens.each { |tk| tk.each { |w| @vocab[w] ||= @vocab.size } }
      @df = Array.new(@vocab.size, 0)
      tokens.each { |tk| tk.uniq.each { |w| @df[@vocab[w]] += 1 } }
      @idf = @df.map { |df| Math.log((texts.size + 1).to_f / (df + 1)) }
      @vectors = texts.each_with_index.map { |t, i| encode(t, tf_source: tokens[i]) }
    end

    def tokenize(text)
      text.downcase.scan(/[a-z0-9_]+/)
    end

    # TF (length-normalized) * IDF, L2-normalized. Sparse Hash vector.
    def encode(text, tf_source: nil)
      tokens = tf_source || tokenize(text)
      counts = Hash.new(0.0)
      tokens.each { |w| counts[@vocab[w]] += 1 if @vocab.key?(w) }
      total = counts.values.sum
      return {} if total.zero?

      vec = {}
      counts.each do |term_idx, tf|
        val = (tf / total) * @idf[term_idx]
        vec[term_idx] = val
      end
      norm = Math.sqrt(vec.values.sum { |v| v * v }) + 1e-9
      vec.transform_values { |v| v / norm }
    end

    def dot(a, b)
      b.sum { |i, v| a.fetch(i, 0.0) * v }
    end
  end
end
