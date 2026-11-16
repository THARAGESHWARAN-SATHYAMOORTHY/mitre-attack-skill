# MITRE ATT&CK skill for Claude

A Claude skill for working with [MITRE ATT&CK](https://attack.mitre.org/). It turns Claude into a
careful ATT&CK analyst that checks every technique ID against live MITRE data instead of quoting
from memory.

## What it does

- **Map** incident reports, logs and threat intel to ATT&CK techniques, with evidence and confidence for each mapping
- **Validate** technique, tactic, group and software IDs and names against the current release
- **Detection coverage**: find which techniques your detections cover and where the gaps are
- **Navigator layers**: generate [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer JSON (format 4.5)
- **Threat modelling and emulation**: profile groups and build emulation plans
- **Sigma and Atomic Red Team**: map rules and tests to techniques
- **Version migration**: move older content (pre-v19 tactics such as "Defense Evasion") to the current structure

It ships a small standard-library-only Python CLI (`attack.py`) that the skill installs on first use.
The CLI downloads the official STIX bundles from
[mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data). No API keys and no
third-party packages are needed.

Baseline: **ATT&CK v20.1** (Enterprise, Mobile, ICS). When MITRE publishes a newer release, the skill
trusts the live data over its own text.

## Install

### Claude Code

```
/plugin marketplace add THARAGESHWARAN-SATHYAMOORTHY/mitre-attack-skill
/plugin install mitre-attack@mitre-attack-skill
```

### Claude.ai / Claude Desktop

1. Download this repo as a zip, then zip just the `skills/mitre-attack` folder.
2. Go to **Settings → Capabilities → Skills** and upload it.

### Claude Agent SDK or a single project

Copy `skills/mitre-attack/` into your project's `.claude/skills/` folder.

## Try it

- "Map this incident report to ATT&CK techniques" (paste the report)
- "Is T1086 still a valid technique ID?"
- "Build a Navigator layer of the techniques APT29 uses"
- "Here are our detection rules. Where are our coverage gaps?"
- "Threat model our web app using ATT&CK"

## Requirements

- Python 3.8 or newer
- Internet access to `raw.githubusercontent.com` the first time the data is downloaded

## Licence

The skill and tool are released under the [MIT licence](LICENSE).

MITRE ATT&CK content is © The MITRE Corporation and is used under the
[ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).
This project is not affiliated with or endorsed by MITRE.
