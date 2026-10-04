# Security

## What gatecall touches

- **What Claude Code hands its hooks**: the text of a message before it is sent, the input of a step before it runs
  (a command, a file path, a web address, a tool's input), and the output of a command, a file read, a search or an
  MCP tool after it ran, looked through for the company's journal key alone. Read in memory, never stored.
- **The company policy file** `company-ai-policy.json` and gatecall's own `data/profiles.json`, read-only.
- **Its journal** `~/.gatecall/journal.jsonl` (or `$GATECALL_HOME`): the time, the folder, the kind of what was
  stopped, the rule, and each value as a fingerprint — HMAC-SHA256 under the company's own key — or, for the kinds
  in `journal_count_only`, only a count. Never the value itself. Each record is kept by the policy of the folder it
  was written in (and by the `$COMPANY_AI_POLICY` of the session that wrote it, which it names) and deleted when that
  policy's `journal_retention_days` (90 by default) are over. A policy with `"journal": false` turns it off.
- **Its key** `journal.key` beside the journal (or the file `journal_key_file` names): 64 hex characters — 32 random
  bytes from `secrets` — used as they stand as the HMAC key, made the first time a value is fingerprinted, never
  replaced. The key, the journal and its exports are readable by their owner only: mode 0600, and on Windows, where a
  file mode does not limit reading, an access list holding the person alone, nothing inherited (`icacls`). The key is
  so from its first byte: it is written in a folder of its own, closed to everyone else before the key is in it, and
  then put in place, so no other user opens it even while it is made. A key file the person owns is set back to 0600
  at every use; one another user owns that others can read is named by `journal`. A key file inside a git work tree
  is listed in that repository's own `.git/info/exclude`, so it is never committed.
- **Writes** only what it is asked to: the permissions block into the file named with `--out`, a cleaned copy into
  the new folder named for `copy`, the training mark into the folder a person names for `mark`, the journal's
  records into the file named for `journal --export`. Outside its own folder it writes one line more, unasked: the
  journal key's path, into `.git/info/exclude` of the repository the key sits in.

## What it never does

- Never sends anything anywhere: Python's standard library only, and no network module is imported (a test fails
  the build if one appears).
- Never prints or keeps a value it stopped: messages carry a masked sample (the last four characters); the journal
  a fingerprint under the company's key, which without the key leads back to no value, not even by trying every
  number of an ID's range.
- Never lets a model open its journal or its key: in every window, a step that reads, searches, edits or names them
  is stopped, a Bash or a PowerShell command too (gatecall's own `journal` and `scan` commands read them); a step that
  reaches the key without naming it has the key taken out of its output before the model reads it (Claude Code
  2.1.227 or later); and the `settings` block closes the key to Claude Code's tools and, with Claude Code's sandbox
  on, to every command, and gatecall's folder to edits.
- Never lets Claude mark a training folder or forge a copy's mark: those are a person's acts.

## Its reach

gatecall guards everything Claude Code sends and runs. Files moved by hand, screenshots and models used outside
Claude Code are held by where the red folders live: on the company's own machines (routecall's `local-red`
profile, firmcall's managed settings).

## Reporting

Open an issue on github.com/vadimchernets/gatecall, or write to the author through the Poly A1 support address.
