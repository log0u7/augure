# Agent snippet: paste into your project's AGENTS.md

```markdown
## augure/lictor - the auditable exploitation decision layer

- augure DECIDES (verified techniques + provenance); lictor ORCHESTRATES
  (authorization + trail). I propose; augure disposes. I never claim a technique
  augure did not rank, and I quote decisions as predictions with
  provenance, never as proven results.
- Loop: `lictor doctor` -> `lictor scan <host> -a targets.yml` ->
  `lictor plan <binary-or-facts> -a targets.yml [--json]` ->
  `lictor outcome <run-id> --success|--failure --technique <t>` ->
  `lictor report`. Full skill: augure/skills/augure-operator/SKILL.md.
- New technique = a PACK (YAML data, never code): copy
  `augure/packs/ret2csu_v2.yml`, validate with `lictor rule validate`,
  install only with operator confirmation. The corpus guard refuses
  packs that move frozen verdicts - read the refusal, fix the data.
- The allowlist file is the scope: targets outside it = never, no
  exceptions. The trail is never edited.
- Payload contract: `--json` emits schema "augure/decision@1".
```
