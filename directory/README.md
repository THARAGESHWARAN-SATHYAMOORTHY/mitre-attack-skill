# Attack Analyst (directory edition)

MITRE ATT&CK skill for Claude. It maps incidents and reports to techniques with evidence and confidence,
checks every ID against attack.mitre.org before answering (revoked IDs are replaced, unknown IDs are
dropped), measures detection coverage, writes ATT&CK Navigator layers, profiles groups, and plans
emulations with Atomic Red Team test IDs.

This edition ships no scripts. Every lookup is a web fetch of the official ATT&CK website, so Claude needs
web access to `attack.mitre.org` (and `github.com` for Atomic Red Team test lists).

## Full edition

The full plugin adds a standard-library Python CLI for bulk validation, coverage scoring from CSV or Sigma
rules, Navigator layer generation and release diffs. It is installed from GitHub:

```
/plugin marketplace add THARAGESHWARAN-SATHYAMOORTHY/mitre-attack-skill
/plugin install attack-analyst@mitre-attack-skill
```

Source, docs and examples: https://github.com/THARAGESHWARAN-SATHYAMOORTHY/mitre-attack-skill

## What you can ask

- "Map this incident report to ATT&CK and validate the IDs."
- "Is T1562.001 still current? What replaced it?"
- "Which of these detections cover what APT29 does? Rank the gaps."
- "Make a Navigator layer of the techniques APT29 and FIN7 share."
- "Migrate this pre-v19 threat model that still says Defense Evasion."

## Privacy

The plugin collects and stores nothing. See [PRIVACY.md](PRIVACY.md).

## Licence

MIT, see LICENSE. ATT&CK content belongs to The MITRE Corporation, see NOTICE.
