---
name: "mitre-attack"
description: "Use for any MITRE ATT&CK work: map incidents/reports to TTPs, validate IDs, detection coverage and gaps, Navigator layers, group profiling, emulation plans, Sigma/Atomic mapping, version migration."
---

# MITRE ATT&CK skill

Baseline: **ATT&CK v20.1** (v20 released 2026-10-13; v20.1 data patch modified 2026-11-05). Facts and the tool below were checked against live STIX data on **2026-11-14**. When live data disagrees with this text (a newer ATT&CK release), trust the live data. ATT&CK ships major releases in April and October plus smaller "Agile" releases (groups/software/campaigns) in between (first: v19.2, Aug 2026).

## Hard rules

1. **State the ATT&CK version** (and domain) in every deliverable. Get it from `attack.py version`.
2. **Verify every ID and name against live data** before output (`get`, or `validate` on the finished draft). Never quote IDs from memory.
3. **Never invent behavior.** Every mapping cites evidence (quote, log line, report page). No evidence, no mapping; inference is marked Low confidence with the reason.
4. **Redact before output.** Strip secrets, API keys, tokens, passwords, hashes of credentials, PII, salary data, and card numbers from any log, ticket, or connector data before it goes into a table, layer comment, or report. Use `[REDACTED-<type>]`.
5. **No weaponization.** Atomic Red Team output is test names, GUIDs, platforms, and executor type only. Do not write exploit code, payloads, or step-by-step attack commands. Emulation plans reference test IDs and are for authorized scope only.
6. Use the most specific sub-technique the evidence supports; otherwise the parent.
7. Enterprise content that says "Defense Evasion" or "14 tactics" is pre-v19: migrate it (workflow E).

## 0. Run the tool and load data (always first)

One standard-library-only CLI ships with this skill at `scripts/attack.py` (in this skill's base directory). Do not rewrite or re-download it; run the bundled file:

```bash
python3 -I <skill-dir>/scripts/attack.py update && python3 -I <skill-dir>/scripts/attack.py version
```

Always run it as `python3 -I <skill-dir>/scripts/attack.py` (below: `attack`), where `<skill-dir>` is this skill's base directory. Data is downloaded to `~/attack-data`. Bundles come from `raw.githubusercontent.com/mitre-attack/attack-stix-data` (`<domain>-attack/<domain>-attack.json`, pinned releases `<domain>-attack-<X.Y>.json`, version list in `index.json`). If GitHub is unreachable, use WebFetch on `https://attack.mitre.org/techniques/<ID>/` and say the data came from the website.

### Commands

Global options (after the command): `-d enterprise|mobile|ics` (default auto: enterprise, then mobile, then ics), `--json`, `--limit N` (table rows, 0 = all), `--full` (untruncated descriptions). Default output is markdown tables. Exit code: 0 ok, 1 validation failed, 2 error.

| Command | What it does |
|---|---|
| `attack update [--force] [--release 19.1]` | Refresh bundles (skips if < 24h old); `--release` saves `<domain>-<X.Y>.json` |
| `attack version` / `attack stats` | Data version per domain / live object counts |
| `attack get <ID or name>` | Full detail for any object (T, TA, G, S, C, M, DET, AN, DC, A): tactics, platforms, parent/subs, mitigations, DET -> AN -> DC with log sources, groups/software/campaigns using it, revoked/deprecated status with replacement chain and what it supersedes |
| `attack search "<text>" [--type group] [--all]` | Ranked search over names, aliases, descriptions (finds "Cozy Bear" -> G0016 APT29) |
| `attack group\|software\|campaign <ID, name or alias>` | Profile: techniques with tactic and source (direct or via campaign), software, campaigns, attribution |
| `attack validate <file or -> [--fix out] [--all]` | Extracts every ID from text/CSV/JSON/Sigma YAML. Flags unknown, revoked (with replacement and its tactic), deprecated, legacy Defense Evasion, tactic-tag mismatch (single Sigma rule), bad sub-technique, parent-vs-sub overlap. `--fix` writes a copy with revoked IDs replaced |
| `attack layer --techniques <csv or ->` | Navigator layer from `technique_id[,score][,comment]` rows (or free text). Revoked IDs are auto-replaced with a warning |
| `attack layer --from <ID...> [--op union\|intersection\|diff] [--with-software]` | Layer for a group/software/campaign, or overlap of several (score = how many use the technique) |
| `attack coverage <detections.csv> [--groups G0016,FIN7] [--top 25] [--layer out.json]` | Rows `technique_id,detection_name,status` with status `none\|logs\|rule\|tested`. Per-tactic coverage %, gaps ranked by number of groups using each technique, optional layer |
| `attack sigma <dir> [--csv out.csv] [--layer out.json] [--groups ...]` | Reads `attack.tXXXX` tags from Sigma rules, reports tag issues, then the same coverage report |
| `attack diff <old> <new> [--type all]` | Added/revoked/deprecated/changed objects between bundles; args are files or `enterprise@19.1` (auto-download) |
| `attack atomic <technique> [--no-subs] [--legacy]` | Atomic Red Team test names, platforms, executor, GUID for a technique and its subs (no commands) |

Examples:

```bash
A="python3 -I <skill-dir>/scripts/attack.py"
$A get T1562                      # revoked -> shows replacement T1685
$A get T0886 --json               # ICS technique, JSON
$A group "Cozy Bear" --limit 0    # full APT29 profile
$A validate draft_report.md       # run on every deliverable before sending
$A layer --from G0016 G0032 --op intersection -o overlap.json
$A coverage detections.csv --groups "APT29,Lazarus Group" --layer coverage.json
$A diff enterprise@19.1 enterprise@20.1
```

Layers use Navigator layer format **4.5** (Navigator 5.3.2, checked 2026-11-14 in `mitre-attack/attack-navigator`: `layers/spec/v4.5/layerformat.md`, `nav-app/package.json`). The tool writes one entry per tactic the technique belongs to, the right domain, and the ATT&CK major version from the data. Coverage scoring: none 0, logs 1, rule 2, tested 3; a parent inherits its best sub-technique score, a sub never inherits from its parent.

## 1. ID formats

| Prefix | Object | STIX type |
|---|---|---|
| TA#### | Tactic | x-mitre-tactic |
| T#### / T####.### | Technique / sub-technique | attack-pattern |
| G#### | Group | intrusion-set |
| S#### | Software | malware / tool |
| C#### | Campaign | campaign |
| M#### | Mitigation | course-of-action |
| DET#### | Detection strategy | x-mitre-detection-strategy |
| AN#### | Analytic | x-mitre-analytic |
| DC#### | Data component | x-mitre-data-component |
| A#### | Asset (ICS) | x-mitre-asset |

Relationships: `uses`, `mitigates`, `detects` (DET -> technique), `subtechnique-of`, `attributed-to` (campaign -> group), `revoked-by`, `targets` (ICS technique -> asset). Analytics hang off a detection strategy via `x_mitre_analytic_refs`; data components via each analytic's `x_mitre_log_source_references`. Filter out `revoked` and `x_mitre_deprecated` unless doing history. ICS techniques are T08xx/T09xx; mobile and enterprise share the T1xxx range, and groups/software can exist in several domains.

## 2. Current structure (v20.1)

### Enterprise: 15 tactics (since v19)

| ID | Tactic | Shortname |
|---|---|---|
| TA0043 | Reconnaissance | reconnaissance |
| TA0042 | Resource Development | resource-development |
| TA0001 | Initial Access | initial-access |
| TA0002 | Execution | execution |
| TA0003 | Persistence | persistence |
| TA0004 | Privilege Escalation | privilege-escalation |
| TA0005 | **Stealth** (was Defense Evasion, same ID) | stealth |
| TA0112 | **Defense Impairment** (new in v19) | defense-impairment |
| TA0006 | Credential Access | credential-access |
| TA0007 | Discovery | discovery |
| TA0008 | Lateral Movement | lateral-movement |
| TA0009 | Collection | collection |
| TA0011 | Command and Control | command-and-control |
| TA0010 | Exfiltration | exfiltration |
| TA0040 | Impact | impact |

Platforms: Windows, macOS, Linux, ESXi, IaaS, Network Devices, PRE, Office Suite, SaaS, Identity Provider, Containers.

### Mobile: 12 tactics (Android, iOS)
Initial Access TA0027, Execution TA0041, Persistence TA0028, Privilege Escalation TA0029, **Defense Evasion TA0030** (the Stealth split was Enterprise only), Credential Access TA0031, Discovery TA0032, Lateral Movement TA0033, Collection TA0035, Command and Control TA0037, Exfiltration TA0036, Impact TA0034.

### ICS: 12 tactics
Initial Access TA0108, Execution TA0104, Persistence TA0110, Privilege Escalation TA0111, Evasion TA0103, Discovery TA0102, Lateral Movement TA0109, Collection TA0100, Command and Control TA0101, Inhibit Response Function TA0107, Impair Process Control TA0106, Impact TA0105. ICS also has 18 assets (A####).

### Live counts, v20.1 (active objects; recompute with `attack stats`)

| Domain | Techniques | Subs | Groups | Software | Campaigns | Mitigations | DET | AN | DC |
|---|---|---|---|---|---|---|---|---|---|
| Enterprise | 227 | 479 | 178 | 842 | 57 | 44 | 706 | 1773 | 106 |
| Mobile | 78 | 47 | 20 | 129 | 3 | 13 | 125 | 213 | 29 |
| ICS | 78 | 26 | 14 | 25 | 10 | 53 | 104 | 300 | 40 |

## 3. Recent changes you must know (all verified in data)

**v18 (Oct 2025): detection model rebuilt.** Data sources were replaced by **Detection Strategies (DET)** -> **Analytics (AN, platform-specific logic with tunables)** -> **Data Components (DC, with log source name and channel)**. One DET per technique.

**v19 (2026-04-28): Defense Evasion split (Enterprise only).**
- TA0005 renamed **Stealth** (hiding: masquerading, obfuscation, hide artifacts, indicator removal).
- New **TA0112 Defense Impairment** (breaking defenses), 57 techniques incl. subs. 60 existing techniques had their tactic list changed.
- 23 new techniques, 17 revoked. Replacement map (`revoked-by`):

| Revoked | Replacement |
|---|---|
| T1562 Impair Defenses, T1562.001, T1562.006 | T1685 Disable or Modify Tools |
| T1562.002 / .008 / .011 / .012 | T1685.001 Windows Event Log / T1685.002 Cloud Log / T1685.003 Modify or Spoof Tool UI / T1685.004 Linux Audit System Log |
| T1070.001 / T1070.002 (log clearing) | T1685.005 Clear Windows Event Logs / T1685.006 Clear Linux or Mac System Logs |
| T1562.004 / .007 / .013 | T1686 Disable or Modify System Firewall / T1686.001 Cloud Firewall / T1686.002 Network Device Firewall (T1686.003 Windows Host Firewall is new) |
| T1562.009 / T1562.010 / T1562.003 | T1688 Safe Mode Boot / T1689 Downgrade Attack / T1690 Prevent Command History Logging |
| T1656 Impersonation / T1672 Email Spoofing | T1684.001 Impersonation / T1684.002 Email Spoofing (under new T1684 Social Engineering, tactic Stealth) |

- Also new in v19: T1687 Exploitation for Defense Impairment, T1682 Query Public AI Services, T1683 Generate Content (.001 Written, .002 Audio-Visual), T1027.018 Invisible Unicode. T1211 renamed Exploitation for Stealth.
- Test for each behavior: **is the actor hiding (Stealth) or breaking a defense (Defense Impairment)?**

**v19.2 (2026-08-05):** first Agile release (groups/software/campaigns).

**v20 (2026-10-13): AI-related techniques.** T1699 Direct Prompt Injection and T1698 Indirect Prompt Injection (Execution), T1700 AI-Enabled Exfiltration (Exfiltration), T1608.007 Stage Capabilities: AI Result Poisoning (Resource Development), T1685.007 Disable or Modify Tools: Impair Autonomous Defenses (Defense Impairment), T1696 Anti-Automation Evasion with .001 Automate CAPTCHA Completion and .002 Avoid CAPTCHA (Stealth), T1697 Steal Application Specific Passwords (Credential Access). Also present: T1588.007 Obtain Capabilities: Artificial Intelligence. No technique revocations between v19.1 and v20.1. Use MITRE ATLAS alongside ATT&CK for attacks on AI systems themselves.

## 4. Workflows

### A. Map a report or incident
1. List each observed behavior as one sentence: actor did X, with Y, on platform Z. Keep the evidence quote and source location. Redact secrets and PII now.
2. For each behavior pick the tactic by the actor's **goal at that step** (table in section 5), then find the technique: `attack search "<verb + object>"`, read `attack get <ID>` description and compare.
3. Choose the most specific sub-technique the evidence supports. Assign confidence.
4. Write the table (template in section 9). Run `attack validate` on the draft; fix every finding.
5. Optional: `attack layer --techniques mapped.csv -o incident.json`.

### B. Detection coverage and gaps
1. Build `detections.csv` (`technique_id,detection_name,status`). From Sigma: `attack sigma rules/ --csv detections.csv`. From SIEM/EDR exports: map each rule to technique IDs, then `validate`.
2. `attack coverage detections.csv --groups <relevant groups> --layer coverage.json`.
3. For each top gap run `attack get <ID>`: read its DET -> AN -> DC rows and compare the log sources to what is actually collected. Missing log source means status stays `none`; collected but no rule means `logs`.
4. Report with the coverage template. Say plainly that coverage % measures mapped rules, not detection quality.

### C. Threat-informed emulation plan
1. `attack group <name>` (or campaign). Add `attack layer --from <ID> --with-software` for the picture including tooling.
2. Order techniques by tactic flow. For each, `attack atomic <ID>` and pick tests by platform; note test GUIDs only.
3. For each step list expected telemetry (DC and log source from `attack get`) and the detection that should fire.
4. Check the CTID Adversary Emulation Library for an existing plan for that actor. Use the emulation template.

### D. Navigator layers
Use `attack layer` (never hand-write tactic names). Open at `https://mitre-attack.github.io/attack-navigator/` -> Open Existing Layer. Group overlap: `--op intersection` for shared tradecraft, `--op diff` for what is unique to the first entity, `union` score = number of entities using each technique (heat map for prioritization).

### E. Migrate pre-v19 or older content
1. `attack validate old.md --fix migrated.md` replaces revoked IDs. It does not change tactic labels or technique names: fix those by hand from the findings.
2. Every Enterprise "Defense Evasion" label: look up the technique's current tactic (`attack get`), which is Stealth or Defense Impairment (or both removed).
3. `attack diff enterprise@<old> enterprise@<new>` lists added, revoked, renamed, and tactic-moved techniques for release notes. Official changelogs: `https://attack.mitre.org/docs/changelogs/`.
4. Record old and new ATT&CK versions in the deliverable.

## 5. Mapping methodology (CISA "Best Practices for MITRE ATT&CK Mapping" style)

Order of work: find the behavior -> research it -> identify the tactic (why) -> identify the technique (how) -> identify the sub-technique -> peer check. Map behaviors, not indicators: an IP address or hash is not a technique.

| Actor goal at this step | Tactic |
|---|---|
| Learn about the target before access | Reconnaissance |
| Build or buy infrastructure, accounts, tools | Resource Development |
| Get in | Initial Access |
| Run code | Execution |
| Keep access across restarts or credential changes | Persistence |
| Get higher permissions | Privilege Escalation |
| Avoid being noticed | Stealth |
| Disable, break, or blind a security control or log | Defense Impairment |
| Steal credentials or tokens | Credential Access |
| Learn the environment after access | Discovery |
| Move to other systems | Lateral Movement |
| Gather target data | Collection |
| Talk to compromised systems | Command and Control |
| Take data out | Exfiltration |
| Destroy, encrypt, disrupt, manipulate | Impact |

Confidence levels:
- **High**: direct evidence of the behavior (command line, log event, malware analysis) matches the technique description.
- **Medium**: behavior is clear but the sub-technique or tactic is inferred from context.
- **Low**: inferred from an outcome or a tool's known capability; state the assumption.

Common mistakes:
- Mapping a tool's full capability list instead of what was observed in this incident.
- One technique per sentence by reflex: one behavior can need two mappings (e.g., a scheduled task is Execution and Persistence only if evidence shows both goals), and many sentences need none.
- Picking the tactic from the technique's first listed tactic instead of the actor's goal.
- Parent used when a sub fits, or a sub guessed when evidence only supports the parent.
- Confusing look-alikes: Valid Accounts (using creds) vs Brute Force (getting them); Exploit Public-Facing Application (initial access) vs Exploitation for Privilege Escalation; Ingress Tool Transfer vs Lateral Tool Transfer; Phishing vs Phishing for Information.
- Using revoked IDs or pre-v19 tactic names. Mixing domains (ICS T08xx in an Enterprise layer).
- Treating mitigations or CVEs as techniques.

## 6. Detection engineering

- Start from `attack get <technique>`: each analytic row gives platform, data components, log source names (e.g., `WinEventLog:Sysmon`, `auditd:SYSCALL`, `AWS:CloudTrail`), and a logic summary. `attack get AN####` adds log channels (event codes) and tunable fields. `attack get DC####` lists every technique detectable from that data component: use it to justify onboarding a log source.
- Analytics are behavioral descriptions, not ready rules. Translate to your SIEM, tune the listed mutable fields, test with an Atomic test, then mark `tested`.
- Tag rules at the most specific level; one rule may carry several techniques.
- **Sigma tags**: lowercase `attack.<tactic-shortname>` and `attack.t1059.001`; also `attack.g0016`, `attack.s0002`. Checked 2026-11-14: sampled rules in SigmaHQ/sigma master already use `attack.defense-impairment` with `attack.t1685` / `attack.t1685.005`, and the Atomic Red Team index uses `stealth` and `defense-impairment`. The Sigma tags appendix (v2.1.0, 2025-08-02) still lists `defense-evasion`, so check the target repo's validators before bulk retagging. `attack sigma` reports legacy tags, revoked IDs, and tactic mismatches per rule.
- Rate robustness, not only presence: CTID Summiting the Pyramid (Sigma `stp.*` tags) scores how hard an analytic is to evade.
- Coverage numbers overstate reality. Report rule count, tested count, and log source availability separately.

## 7. Threat intelligence

- Profile: `attack group <alias>` gives techniques (direct and via attributed campaigns), software, and campaigns. Group pages lag current reporting; note the group object's modified date and add recent vendor reporting with citations.
- Aliases are vendor-specific and overlap imperfectly. Say "tracked by MITRE as G0016 (APT29)" and keep vendor names as reported.
- Overlap: `attack layer --from A B C --op intersection` for common tradecraft worth detecting first; `union` scores for sector heat maps. Shared techniques do not prove shared identity.
- Prioritize by: groups targeting the organization's sector and region, then techniques seen in recent campaigns (C####), then prevalence (`coverage` gap ranking).
- Software-heavy actors (and most Mobile/ICS groups) need `--with-software` to show real technique use.

## 8. Purple teaming and cross-framework links

| Resource | Use | Note |
|---|---|---|
| Atomic Red Team (redcanaryco/atomic-red-team) | Small per-technique tests; `attack atomic <ID>` | Enterprise only; already on v19+ IDs. Names and GUIDs only in outputs |
| MITRE Caldera (github.com/mitre/caldera) | Automated adversary emulation with ability-to-technique mapping | README now references apache/caldera; confirm current home |
| CTID Adversary Emulation Library (center-for-threat-informed-defense/adversary_emulation_library) | Full and micro emulation plans per actor | Check which ATT&CK version each plan used |
| D3FEND (d3fend.mitre.org) | Defensive countermeasures mapped to ATT&CK techniques | Use for "what control counters this" |
| MITRE Engage (engage.mitre.org) | Adversary engagement, deception, and denial activities | Pair with emulation and detection plans |
| ATLAS (atlas.mitre.org) | Attacks on AI/ML systems | Pair with T1698-T1700, T1608.007, T1685.007 |
| CAPEC / CWE | Attack patterns and weaknesses | Some techniques carry `capec` external references |
| CTID Mappings Explorer (ctid.mitre.org/mappings) | NIST 800-53, cloud platform controls, CVE and KEV to ATT&CK | Each mapping set is pinned to an ATT&CK version: check it, then `validate` the IDs |
| CISA KEV catalog | Exploited CVEs for prioritizing T1190 / T1203 / T1068-type gaps | Map CVE -> technique via Mappings Explorer, not by guess |
| Mitigations (M####) | `attack get <technique>` lists them; `attack get M####` lists techniques covered | Link to NIST 800-53 through Mappings Explorer |

Purple team loop: pick techniques from the gap list -> select Atomic tests -> run in authorized scope -> record which detection fired -> update `detections.csv` status to `tested` -> regenerate the layer.

## 9. Output templates

**Incident / report mapping** (header line: "ATT&CK Enterprise v20.1, mapped <date>, source <doc>")

| # | Time (UTC) | Evidence (redacted quote + source) | Tactic | Technique ID | Technique name | Confidence | Notes |
|---|---|---|---|---|---|---|---|

Follow with: unmapped behaviors and why, assumptions, validation result (`attack validate`: PASS).

**Coverage report**
1. Scope: ATT&CK version, domain, platforms, rule sources, date.
2. Summary: techniques with rule or better (n of N), tested (n), by tactic table (from `coverage`).
3. Top gaps table: Technique | Tactic | Groups using | Required data components | Log source present? | Recommended action | Owner.
4. Tag hygiene issues (revoked IDs, legacy tactics). 5. Navigator layer file. 6. Limits: coverage is not efficacy.

**Emulation plan**
1. Objective, authorized scope, rules of engagement, ATT&CK version, actor (G####/C####) with sources.
2. Step table: # | Tactic | Technique ID and name | Test reference (Atomic GUID or Caldera ability) | Platform | Expected telemetry (DC / log source) | Expected detection | Result.
3. Safety: test accounts and hosts only, cleanup steps, stop conditions. 4. Findings feed back into `detections.csv`.

## Sources
- Data: https://github.com/mitre-attack/attack-stix-data (index.json lists releases)
- Release notes: https://attack.mitre.org/resources/updates/ ; changelogs: https://attack.mitre.org/docs/changelogs/
- Navigator: https://github.com/mitre-attack/attack-navigator (layers/spec/v4.5/layerformat.md)
- Sigma tags: https://github.com/SigmaHQ/sigma-specification (specification/sigma-appendix-tags.md)
- Atomic Red Team: https://github.com/redcanaryco/atomic-red-team (atomics/Indexes/Indexes-CSV/index.csv)
- CISA mapping guide: https://www.cisa.gov/news-events/news/best-practices-mitre-attckr-mapping