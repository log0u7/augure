---
name: augure-operator
description: Operate the augure/lictor auditable exploitation decision layer - verify environments, decide techniques on fact files, run allowlist-checked scans, record outcomes, write validated technique packs. Use when the user says augure, lictor, "which technique on this target", technique pack, or asks to analyze a binary/CTF target with an auditable decision layer.
---

# Operating augure + lictor

## The mental model (read this first)

- **augure decides**: it ranks verified techniques from Datalog facts.
  You PROPOSE; augure DISPOSES. You cannot pick a technique that is not
  applicable/verified - that is the point. Never claim a technique
  augure did not select.
- **lictor executes the logistics**: scans, profiling, recipes, the
  trail. The allowlist and the consent tokens are the law; work
  around them and you are out.
- **Decisions are predictions with provenance** (rule ID + evidence +
  seed). Quote them as such - never as field-proven results.
- You improvise BETWEEN the steps (which binary, which input, what the
  crash means) - never against the rules.

## The full chain (13 steps, all recorded in the trail)

```sh
lictor init                                 # fresh setup (scaffolds config)
lictor doctor                               # verify env, exact fix per check
lictor scan <host> -a targets.yml           # nmap; the target must be in the allowlist
lictor acquire <target> --from <url>        # the nmap->binary bridge (or --bin <path>)
lictor fuzz <binary>                        # discovery: sweep + triage -> facts
lictor verify <target> --input crash-input.bin  # the differential: remote-verified
lictor suggest <facts> "plt(\"system\")."    # propose observations, augure re-decides (delta back)
lictor plan <binary-or-facts> -a targets.yml [--json]   # decide (schema: augure/decision@1)
lictor build <binary> --facts <facts>       # MEASURED offset + fact-sourced return -> payload file
lictor authorize <target>                   # the operator TYPES the target -> token (15 min)
lictor run <target> --facts <f> -a targets.yml --executor ronin --consent-token <t>
                                            # decide -> execute -> outcome -> re-decide
lictor outcome <run-id> --success --technique <t>   # feed the closed loop
lictor report -o engagement.md              # the auditable deliverable
```

Confidence levels: profiler facts are MODELED (from the acquired
binary); `lictor verify` upgrades them to remote-verified (the remote
faults like the local model). Quote the level in reports.

Read the `explain` payload: it tells you WHY (rule + facts). If a
decision surprises you, the disagreement is signal - check which fact
you are missing before doubting the rule.

## Writing a technique pack (teaching augure)

1. Read `docs/pack-format.md` in the augure repo (the format, the
   6 armor checks).
2. Copy `packs/ret2csu_v2.yml` (the canonical example) - change the
   substance, keep the structure.
3. Conditions: ONLY `[fact, rel, val]`, `[not_fact, rel, val]` (input
   facts only), `[match, rel, idx, pattern]`, `[cmp, rel, op, n]`.
   Predicates: the 27 input facts (binary vocabulary + the network
   vocabulary from nmap scans: service/software_version/remote; the
   confidence marker: verified) + built-in derived relations. Nothing
   invented.
4. Validate BEFORE proposing to anyone:
   `lictor rule validate pack.yml` - each refusal names the
   check that failed; fix the data, never bypass the armor.
5. Install only with explicit operator confirmation (interactive or
   consent token). Rules change every future decision - that is why.

## Hard rules (violating these = you are the vulnerability)

- Targets outside `targets.yml` = never. The allowlist is the scope
  document; do not suggest entries you have not verified against the
  engagement contract.
- Exploit names come from the operator's ronin repos - never invent one.
- Packs contain data, never code. If a pack needs code, the technique
  is not a pack.
- The trail is sacred: never suggest deleting or editing it.
- Claims discipline: rankings are prior-mean predictions; success rates
  are authored numbers. Report them as that.
