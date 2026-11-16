# Contributing

Thanks for helping keep ATT&CK mappings honest.

## Good first contributions

- **After a new ATT&CK release:** run `python3 -I tools/attack.py diff enterprise@20.1 enterprise@<new>`, then update the
  version notes, tactic tables and "recent changes" section in `skills/mitre-attack/SKILL.md`.
- **New workflows or output templates** (for example a cloud-specific coverage report).
- **Bug reports** for `attack.py`: include the command, the ATT&CK version (`attack.py version`) and the output.

## Rules for changes

1. **Verify every ID** you add with `attack.py get` or `attack.py validate`. Never write IDs from memory.
2. **Keep `attack.py` standard-library only.** No third-party packages.
3. **Keep the two copies in sync.** The tool lives inside `SKILL.md` (between the `PYEOF` markers) and in
   `tools/attack.py`. Edit `SKILL.md`, then copy the block into `tools/attack.py`.
4. **No weaponisation.** No exploit code, payloads or step-by-step attack commands. Atomic Red Team output stays at
   test names and GUIDs.
5. **Bump `version`** in `.claude-plugin/plugin.json` when the skill changes, or installed copies won't update.

## Testing a change locally

```bash
claude plugin validate .
python3 -I tools/attack.py update -d enterprise
python3 -I tools/attack.py validate skills/mitre-attack/SKILL.md -d enterprise
```
