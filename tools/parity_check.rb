# frozen_string_literal: true

# Static-parity harness: the frozen corpus claims facts about the 8
# documented ROP Emporium targets; this tool downloads the REAL binaries
# (sha256-pinned zips), profiles binary + shipped libraries, and asserts
# every statically-derivable claim. Write-up facts no ELF can carry
# (source-level hints, runtime vuln classes) are reported as skipped,
# never as failures. The binaries are read-only inputs: nothing here
# executes them.
#
# Usage: bundle exec ruby tools/parity_check.rb [--cache DIR]

require "digest"
require "fileutils"
require "net/http"
require "open3"
require "tmpdir"

require "augure"
require "augure/parity"
require "augure-profiler"

module ParityCheck
  ZIPS = {
    "ret2win" => "448c75375dcbe3c926c5ca66a1bb9314d53d05c412f22e528da1e3bced9dbef2",
    "split" => "85ecb74a9fd691f10da52a1122b00ce5713aadc779dd5e0ca21c364a03ff619e",
    "callme" => "a32deecd2f018bca0d2cce7e4ece2f60c08e3915e97f30f4d30e8d61ebf20741",
    "write4" => "3925c857cf71cbd218604f733faa7beafe520459bdfdee46d02c3c9033ad042f",
    "badchars" => "f6e8d54c004a5ad658bbd85c55777f82de897f863313d8a1c31d8417ce114425",
    "fluff" => "a2d3ab1dbc201d5064845ae3ca1230b2da9f75aabd5f83bf46b92918a2769a76",
    "pivot" => "afea7618a3795a703ae31d310975c5109275ac9a216468fd744fac351761c0a7",
    "ret2csu" => "fa45c8f5e2df81bc6941ec46d988e52079b7d11103fcce7fbf93ba76cc0ff888"
  }.freeze
  BASE_URL = "https://ropemporium.com/binary"

  module_function

  def supported_gadget_types
    (AugureProfiler::Profiler::GADGET_PATTERNS.map { |type, _| type } +
      %w[csu_popper csu_mov]).uniq
  end

  def fetch(name, digest, cache)
    zip = File.join(cache, "#{name}.zip")
    dir = File.join(cache, name)
    unless File.file?(zip) && Digest::SHA256.file(zip).hexdigest == digest
      uri = URI("#{BASE_URL}/#{name}.zip")
      body = Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: 15,
        read_timeout: 60) { |http| http.get(uri.request_uri) }.body.to_s
      raise "downloaded #{name}.zip but its sha256 does not match the pin" unless Digest::SHA256.hexdigest(body) == digest

      File.binwrite(zip, body)
    end
    FileUtils.mkdir_p(dir)
    _out, err, status = Open3.capture3("unzip", "-oq", zip, "-d", dir)
    raise "unzip failed for #{name}: #{err}" unless status.success?
    dir
  end

  # The target = the main ELF + every library shipped next to it: facts
  # from both are merged (Facts#merge), exactly what the write-ups
  # describe when they say "the binary and its library".
  def observed_facts(dir)
    elfs = Dir.children(dir).select do |f|
      path = File.join(dir, f)
      File.file?(path) && !File.directory?(path) && elf?(path)
    end
    raise "no ELF found in #{dir}" if elfs.empty?

    elfs.map { |f| AugureProfiler::Profiler.new(File.join(dir, f)).facts }
      .reduce { |acc, facts| acc.merge(facts) }
  end

  def elf?(path)
    File.open(path, "rb") { |f| f.read(4) == "\x7fELF" }
  rescue
    false
  end

  def corpus_targets
    corpus = JSON.parse(File.read(File.expand_path("../lib/augure/ctf_corpus.json", __dir__)))
    corpus.fetch("suites").fetch("ropemporium")
  end

  def run(cache)
    results = corpus_targets.map do |entry|
      dir = fetch(entry.fetch("name"), ZIPS.fetch(entry.fetch("name")), cache)
      observed = observed_facts(dir)
      Augure::Parity.check(observed, entry, supported_gadget_types: supported_gadget_types)
    end
    results.each do |r|
      line = "  #{r.target.ljust(10)} checked=#{r.checked} skipped=#{r.skipped.size}"
      if r.ok?
        puts "#{line}  ok"
      else
        puts "#{line}  MISSING: #{r.missing.map(&:inspect).join(", ")}"
      end
    end
    total_skipped = results.sum { |r| r.skipped.size }
    puts "  parity: #{results.count(&:ok?)}/#{results.size} targets, " \
      "#{results.sum(&:checked)} claims checked, #{total_skipped} skipped " \
      "(source-level or outside the pattern vocabulary)"
    results.all?(&:ok?) || raise("parity failed: a statically-derivable corpus claim was not observed")
  end
end

if $PROGRAM_NAME == __FILE__
  cache = (ARGV[0] == "--cache") ? ARGV.fetch(1, "/tmp/ropemporium_parity") : "/tmp/ropemporium_parity"
  FileUtils.mkdir_p(cache)
  ParityCheck.run(File.expand_path(cache))
end
