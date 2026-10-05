---
name: augure-operator
description: Operate the augure/lictor auditable exploitation decision layer - verify environments, decide techniques on fact files, scan targets, record outcomes, write validated technique packs. Use when the user says augure, lictor, "which technique on this target", technique pack, or asks to analyze a binary/CTF target with an auditable decision layer.
---

# Operating augure + lictor

## The mental model (read this first)

- **augure decides**: it ranks verified techniques from Datalog facts.
  You PROPOSE; augure DISPOSES. You cannot pick a technique that is not
  applicable/verified - that is the point. Never claim a technique
  augure did not select.
- **lictor executes the logistics**: scans, profiling, recipes, the
  trail. You are the operator: what runs, you ran it; work
  around them and you are out.
- **Decisions are predictions with provenance** (rule ID + evidence +
  seed). Quote them as such - never as field-proven results.
- You improvise BETWEEN the steps (which binary, which input, what the
  crash means) - never against the rules.

## The full chain (15 steps, all recorded in the trail)

```sh
lictor init                                 # fresh setup (scaffolds config)
lictor doctor                               # verify env, exact fix per check
lictor scan <host>                           # nmap; the scan is trailed
lictor acquire <target> --from <url>        # the nmap->binary bridge (or --bin <path>)
lictor fuzz <binary>                        # discovery: sweep + triage -> facts
lictor verify <target> --input crash-input.bin  # the differential: remote-verified
lictor suggest <facts> "plt(\"system\")." -o <facts>   # propose observations, augure re-decides; -o writes the merged base
lictor harvest <target> --facts <facts>      # the banner's hex leaks -> leaked_address facts
lictor plan <binary-or-facts> [--json]   # decide (schema: augure/decision@1)
lictor build <binary> --facts <facts>       # MEASURED offset + fact-sourced return -> payload
                                            # ROP chains: chain slots resolve gadget:/plt_addr:/got_addr:/leak:/const: from the facts
                                            # seccomp("true") in the facts: the sh stub switches to the orw chain
lictor run <target> --facts <f> --executor ronin --flag-regex "FLAG\\{[^}]+\\}"
                                            # decide -> execute -> outcome -> re-decide; the flag in the output is the oracle,
                                            # and the output's hex leaks become facts for the next attempt
lictor exploit scaffold <technique> <binary> --facts <facts> --repo-dir DIR   # draft the ronin exploit (review before commit)
lictor draft <facts> [binary]   # nothing applies? the observations become a staged pack
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
   decision). Rules change every future decision - that is why.

## Hard rules (violating these = you are the vulnerability)

- Authorized use only. The operator decides the scope; suggest only
  targets they have named. You are responsible for the legality where
  you stand.
- Exploit names come from the operator's ronin repos - never invent one.
- Packs contain data, never code. If a pack needs code, the technique
  is not a pack.
- The trail is sacred: never suggest deleting or editing it.
- Claims discipline: rankings are prior-mean predictions; success rates
  are authored numbers. Report them as that.
