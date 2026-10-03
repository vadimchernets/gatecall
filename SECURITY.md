# Security

## What gatecall touches

- **What Claude Code hands its hooks**: the text of a message before it is sent, and the input of a step before
  it runs (a command, a file path, a web address, a tool's input). Read in memory, never stored.
- **The company policy file** `company-ai-policy.json` and gatecall's own `data/profiles.json`, read-only.
- **Its journal** `~/.gatecall/journal.jsonl` (or `$GATECALL_HOME`): the time, the kind of what was stopped, the
  rule and a short sha256 fingerprint. Never the value itself. A policy with `"journal": false` turns it off.
- **Writes** only what it is asked to: the permissions block into the file named with `--out`, a cleaned copy into
  the new folder named for `copy`, the training mark into the folder a person names for `mark`.

## What it never does

- Never sends anything anywhere: Python's standard library only, and no network module is imported (a test fails
  the build if one appears).
- Never prints or keeps a value it stopped: messages and the journal carry a masked sample (the last four
  characters) and a fingerprint.
- Never lets Claude mark a training folder or forge a copy's mark: those are a person's acts.

## Its reach

gatecall guards everything Claude Code sends and runs. Files moved by hand, screenshots and models used outside
Claude Code are held by where the red folders live: on the company's own machines (routecall's `local-red`
profile, firmcall's managed settings).

## Reporting

Open an issue on github.com/vadimchernets/gatecall, or write to the author through the Poly A1 support address.
