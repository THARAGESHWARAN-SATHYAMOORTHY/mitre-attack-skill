# Privacy policy

Applies to the Attack Analyst plugin (directory edition), last updated 2026-11-16.

## What the plugin collects

Nothing. The plugin is a set of instructions for Claude. It has no server, no account, no analytics, no
telemetry and no tracking, and its author receives no data from anyone who uses it.

## What leaves your machine

To check ATT&CK IDs, Claude fetches public pages from:

- `attack.mitre.org` (techniques, tactics, groups, software, campaigns, mitigations, detection strategies)
- `github.com/redcanaryco/atomic-red-team` (Atomic Red Team test lists, only when you ask for them)

These requests carry only the ATT&CK ID or search words in the page address. Your incident reports, logs,
detections and other content are not sent to these sites. Those sites' own privacy policies apply to the
requests they receive.

## What the plugin stores

Nothing. It writes no files of its own. Any file it produces, such as a Navigator layer, is written only when
you ask for it and stays where you saved it.

## Sensitive content

The skill tells Claude to redact secrets, credentials and personal data from any log or report before
putting it into a table, layer comment or report.

## Contact

Questions: open an issue at https://github.com/THARAGESHWARAN-SATHYAMOORTHY/mitre-attack-skill/issues
