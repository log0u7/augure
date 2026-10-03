# How to: write a technique rule

Assumes you have run the tutorial and understand the fact format. Goal: add
a rule to the applicability table with test coverage and provenance.

## 1. Add the rule to the table

Open `lib/augure/rules.rb`. Rules live in one place - the table IS the
engine. Add yours where it belongs in the reading order:

```ruby
b.rule :app_my_technique, ["applicable", "my_technique"],
       source: "one line: when does this fire and why" do |c|
  c.fact "vuln", "sof"
  c.fact "nx", "true"
  c.fact "plt", "pwnme"
end
```

Condition vocabulary:

| Condition | Meaning |
|---|---|
| `c.fact rel, val` | a tuple `rel("val")` exists |
| `c.not_fact rel, val` | that tuple is absent (input relations only) |
| `c.match rel, idx, "pattern"` | arg `idx` matches the regex |
| `c.cmp rel, :ge, 26` | an integer arg satisfies the comparison |

## 2. Test it (before the rule exists in your head, after in the file)

```ruby
# spec/augure/engine_spec.rb
it "fires my_technique when pwnme is imported" do
  f = "vuln(\"sof\").\nnx(\"true\").\nplt(\"pwnme\").\n"
  expect(applicable(f)).to include("my_technique")
end

it "does not fire my_technique without NX" do
  f = "vuln(\"sof\").\nnx(\"false\").\nplt(\"pwnme\").\n"
  expect(applicable(f)).not_to include("my_technique")
end
```

Run `bundle exec rspec`. If the frozen CTF corpus conformance spec now fails,
your rule changed an existing decision: that is either a bug in the rule or
an improvement - update the corpus entry and say which, in the commit.

## 3. Check the provenance appears

```sh
bundle exec ruby -e '
require "augure"
r = Augure::Pipeline.analyze(facts: "vuln(\"sof\").\nnx(\"true\").\nplt(\"pwnme\").\n")
p r[:explain][:provenance]["my_technique"]
'
```

You should see `rule: :app_my_technique` with the evidence pairs. That is
the audit payload - it is automatic, you earned it by using the table.

## Rules of the road

- **One rule, one reason.** Split OR-conditions into sibling rules sharing a
  head; the provenance then tells *which* reason fired.
- **Negation on inputs only.** `not_fact` on a derived relation breaks
  stratification; the corpus conformance spec will catch it loudly.
- **Defaults are closed-world.** Absent `nx` means `nx("true")` - document
  any rule that depends on absence.
- **The corpus is the contract.** A rules commit that moves a corpus verdict
  must update `lib/augure/ctf_corpus.json` in the same commit and justify
  the move in the message.
