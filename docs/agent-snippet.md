# Agent snippet: paste into your project's AGENTS.md

```markdown
## augure/lictor - the auditable exploitation decision layer

- augure DECIDES (verified techniques + provenance); lictor ORCHESTRATES
  (authorization + trail). I propose; augure disposes. I never claim a technique
  augure did not rank, and I quote decisions as predictions with
  provenance, never as proven results.
- Loop (all recorded in the trail): `lictor doctor` ->
  `lictor scan <host> -a targets.yml` -> `lictor acquire <target>
  --from <url>|-bin <path>` -> [optional discovery: `lictor fuzz`,
  `lictor verify`] -> `lictor suggest <facts> "plt(\"system\")."`
  (propose observations; the delta comes back) -> `lictor plan
  <binary-or-facts> -a targets.yml [--json]` -> `lictor build <binary>
  --facts <facts>` (offset measured, payload file) ->
  `lictor exploit scaffold <technique> <binary> --facts <facts>
  --repo-dir DIR` (no exploit in the repos? the draft lands, review it)
  -> `lictor draft <facts> [binary]` (nothing applies? a staged pack)
  -> `lictor authorize <target>` (typed token) ->
  `lictor run <target> --facts <f> --executor ronin --consent-token <t>`
  -> `lictor outcome <run-id> --success|--failure --technique <t>` ->
  `lictor report`. Full skill: augure/skills/augure-operator/SKILL.md.
- New technique = a PACK (YAML data, never code): copy
  `augure/packs/ret2csu_v2.yml`, validate with `lictor rule validate`,
  install only with operator confirmation. The corpus guard refuses
  packs that move frozen verdicts - read the refusal, fix the data.
- The allowlist file is the scope: targets outside it = never, no
  exceptions. The trail is never edited.
- Payload contract: `--json` emits schema "augure/decision@1".
```
