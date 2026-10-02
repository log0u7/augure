# frozen_string_literal: true

require "json"
require "augure-mcp"
require "tmpdir"
require "open3"
require_relative "../profiler/support/binary_builder"

RSpec.describe AugureMcp::Server do
  let(:server) { described_class.build }

  it "exposes exactly three read-only tools" do
    expect(server.tools.values.map(&:tool_name))
      .to contain_exactly("analyze_target", "list_rules", "explain_technique")
  end

  it "answers a tools/call over JSON-RPC with a provenance-carrying decision" do
    response = server.handle_json(
      %({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"analyze_target",
         "arguments":{"facts":"nx(\\"true\\").\\npie(\\"false\\").\\ncanary(\\"false\\").\\nplt(\\"system\\").\\ngadget(\\"pop_rdi_ret\\", 1).\\nvuln_hint(\\"unsafe_func:gets\\").\\n"}}})
    )
    body = JSON.parse(response)
    text = body.dig("result", "content", 0, "text")
    decision = JSON.parse(text)
    expect(decision["ranking"].first).to eq("ret2plt")
    expect(decision.dig("explain", "provenance", "ret2plt")).not_to be_empty
  end

  it "returns the rules table and technique explanations" do
    rules = JSON.parse(server.handle_json(
      %({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_rules","arguments":{}}})
    ))
    ids = JSON.parse(rules.dig("result", "content", 0, "text"))["rules"].map { |r| r["id"] }
    expect(ids).to include("app_ret2plt")

    explained = JSON.parse(server.handle_json(
      %({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"explain_technique","arguments":{"technique":"ret2plt"}}})
    ))
    explained = JSON.parse(explained.dig("result", "content", 0, "text"))
    expect(explained["technique"]).to eq("ret2plt")
    expect(explained["rules"]).not_to be_empty
    expect(explained["knowledge"]).not_to be_empty
  end

  it "smoke: runs as a real stdio server" do
    Dir.mktmpdir do |dir|
      dir = BinaryBuilder.build(dir)
      binary = File.join(dir, "vuln_nx_off_nopie")
      facts, _err, _ = Open3.capture3(File.expand_path("../../profiler/exe/augure-profile", __dir__), binary)
      exe = File.expand_path("../../mcp_server/exe/augure-mcp", __dir__)
      params = JSON.generate({name: "analyze_target", arguments: {facts: facts}})
      request = %( {"jsonrpc":"2.0","id":1,"method":"tools/call","params":#{params}} ) + "\n"
      out, err, s = Open3.capture3("bundle", "exec", exe, stdin_data: request)
      expect(s.exitstatus).to eq(0), "exit #{s.exitstatus}, stderr: #{err.lines.first(3).join}"
      response = json_lines(out).find { |j| j["id"] == 1 }
      expect(response).not_to be_nil, "no JSON-RPC response on stdout; got: #{out[0, 300].inspect}"
      text = response.dig("result", "content", 0, "text")
      expect(text).not_to be_nil, "no tool text in response: #{response.inspect[0, 300]}"
      expect(JSON.parse(text)["ranking"].first).to eq("shellcode")
    end
  end

  def json_lines(out)
    out.lines.map(&:chomp).compact.filter_map do |line|
      JSON.parse(line)
    rescue StandardError
      nil
    end
  end
end
