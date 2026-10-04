# gatecall

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23116724.svg)](https://doi.org/10.5281/zenodo.23116724)

What may leave the company, and where it may go. A [Claude Code](https://claude.com/claude-code) plugin of
Poly A1 for a company's people and the one who sets AI up. Repository:
[github.com/vadimchernets/gatecall](https://github.com/vadimchernets/gatecall).

**gatecall gives every kind of data a route.** Red folders are read only by a model on this computer; the
company's work goes to the company's own accounts; and a key, a card number, an IBAN, an ID number or a list of
people's addresses never leaves in a message by accident. It stops, explains and shows the way forward; it sends
nothing and buys nothing.

## What it does

| Part | What the company gets |
|---|---|
| Hooks | Before a message leaves: keys and tokens, card numbers (Luhn-checked), IBANs (mod-97), national ID numbers with their check digit (US, UK, Spain, Portugal, Brazil, France, Italy, Germany, the Netherlands, Poland, Ukraine, Russia), and lists of e-mail addresses or phone numbers stop it, with the reason in the person's language. Before a step: the same for commands, web requests and tool calls; red folders are read only in the red window — a model on this computer with routecall's `profile local-red` mark (`ROUTECALL_WINDOW=local-red`), where no web tool and no network program to an outside host runs; every other session, an ordinary local one included, is kept out of them. gatecall's own journal and key are opened by gatecall alone, and after a step the company's journal key is taken out of whatever output reached it. |
| Profiles | `default`, `eu` (every EU country's ID numbers; a list counts from three), `us-federal-contractor` (no DeepSeek model, API or weights; no API of Zhipu, which is on the US Entity List - its open GLM weights still run here), `us-dod-strict` (the wider list a contract may ask for). They add up. |
| Programs | kimi works only in a training folder of practice files; grok only on a cleaned copy (`copy`: no red folder, no key file, no `.git`; inside every file — office documents too — keys, cards, IBANs, ID numbers and lists of people are masked as `[card ********7899]`, and what cannot be read as text, such as a PDF or an image, stays out and is named with the reason); agy never gets a permission for everything. |
| Countries and vendors | `deny_jurisdictions` in the policy closes every model API host that processes data in those countries (a Singapore host of the same vendor stays open; weights on this computer still run); `deny_providers` closes a vendor's hosts and model names. The hosts table in `data/profiles.json` names each host's vendor, country and source page. |
| `settings` | The `permissions.deny` block for Claude Code: Read and Edit of every red folder by its absolute `//path` and of the journal's key, Edit of gatecall's own folder, and WebFetch of the hosts a profile denies. |
| `route` | Where red, yellow and green data go, from the company's policy. |
| `scan` | What in a file would be stopped, masked; `--json` adds each value's fingerprint under the company's key and that key's `key_id`. |
| `journal` | What was stopped, by kind and rule, and how often the same value came back; each value only as a fingerprint under the company's own key or as a count, each record kept by the policy of the folder it was written in. `--export` gives the records as JSON Lines or CSV. |

## Installing

From the Poly A1 catalogue, by its link — no git and no account needed:

```
/plugin marketplace add https://raw.githubusercontent.com/vadimchernets/poly-a1-plugins/main/.claude-plugin/marketplace.json
/plugin install gatecall@poly-a1
```

Then say "set up the data rules for our company". The skill asks which folders are red and yellow, writes
`company-ai-policy.json` (see `data/company-ai-policy.example.json`) and the permissions block.

## The company policy file

`company-ai-policy.json` is shared by the company plugins (firmcall writes it; gatecall, routecall and billcall
read it). gatecall reads `profiles`, `country`, `language`, `deny_jurisdictions`, `deny_providers`, `deny_hosts`, `deny_models`, `red_paths`, `yellow_paths`, `training_folders`,
`copy_folders`, `markers`, `journal`, `journal_retention_days`, `journal_count_only`, `journal_key_file` and `fail_closed` (true: a message or a step the guard itself could not
check is stopped; by default the session goes on and the failure is journaled). It is looked for in this order: the managed copy an administrator
installed (`/Library/Application Support/ClaudeCode/`, `/etc/claude-code/`, `C:\Program Files\ClaudeCode\`), then
`$COMPANY_AI_POLICY`, then the project folder and its `.claude/`, then each folder above it the same way — a policy in
the company folder holds in every folder inside it — then `~/.claude/`.

## The journal

`~/.gatecall/journal.jsonl` (or `$GATECALL_HOME`) has one line per stop: the time, the folder, the tool, the kinds,
the rules and `keep_until`, the end of the record's retention period. It holds no stopped value. Each value is there
as a fingerprint — HMAC-SHA256 under the company's own key — so the same card stopped twice shows as one repeat, and
without the key trying every possible number against a fingerprint finds nothing. With the key, the company checks a
number it already has against the journal: `scan --json` gives the same fingerprints, each with the `key_id` of the
key it was made under, as every record carries it; it reads the key and never makes one, and where a value has no
fingerprint it says why. The kinds named in `journal_count_only`, such as `["national-id"]`, are kept only as a
count, with no fingerprint to check at all (`true` keeps every kind so, and makes no key); a kind moved to a count
later loses the fingerprints its records had at the next pass, and is never shown or exported with them.

- **The key** is the text of `journal.key` beside the journal: 64 hex characters (32 random bytes from Python's
  `secrets`), made the first time a value is fingerprinted, never replaced, and used as it stands as the HMAC key. A
  fingerprint is the first 16 hex characters of HMAC-SHA256 over the value as gatecall reads it: a card's digits, an
  IBAN without spaces, an ID number without spaces, dots or dashes in capitals, a key or a token as written; a list of
  addresses is its addresses in lower case, sorted, one a line (a list of phone numbers, their digits), so two
  different lists are two values. The security team checks a card so:
  `printf %s 4000001234567899 | openssl dgst -sha256 -hmac "$(cat ~/.gatecall/journal.key)"`.
  `journal_key_file` in the policy (a relative path is read from the policy file's folder), or `$GATECALL_KEY_FILE`,
  names another file: one key installed on every laptop makes their journals comparable. Every record names its key
  by `key_id` (a short HMAC of a fixed text), and fingerprints under two keys are never compared. A key file inside a
  git work tree is listed in that repository's own `.git/info/exclude`, so `git add -A` never takes it.
- **Each folder's rules**: the journal is one file per person, and each record is kept by the policy of the folder it
  was written in — its retention period, its count-only kinds, its key — whichever folder the journal is tended or
  read from. `$COMPANY_AI_POLICY` belongs to a session (a terminal may have it and the desktop app not): a record
  written under it names it (`company_ai_policy`) and is kept by it in every session. A record whose folder no policy
  covers any more is kept until its `keep_until`.
- **Retention**: a record past its folder's `journal_retention_days` (90 by default; a period shortened since counts
  for the records already kept) is deleted by a pass that runs in the background at every session start and whenever
  a stop finds one due, and before `journal` shows or exports anything; a record past its period is never shown or
  exported. A stop only adds its line, so no hook waits on a pass.
- **Hooks at once**: the journal's lock is the kernel's (`flock`; a locked byte on Windows), and it is gone with a
  hook that is killed. A stop that cannot have the lock within 2 seconds is written to `journal.pending/` and joins the
  journal at the next pass, exactly once.
- **Export**: `gatecall.py journal --export FILE [--format jsonl|csv] [--days N]` writes every kept record (or those
  of the last N days) for the company's security team; `-` writes them to the screen.
- **Only gatecall opens these files**: in every window, a step that reads, searches, edits or names the journal's
  folder or the key is stopped, a Bash or a PowerShell command too — gatecall's own `journal` and `scan` read them. A
  step that reaches the key without naming it, such as a search over a folder that holds it, has the key taken out of
  its output before Claude reads it (a PostToolUse hook; Claude Code 2.1.227 or later), and the stop is journaled.
  The `settings` block closes the key to Claude Code's tools and, with Claude Code's sandbox on, to every command, and
  gatecall's folder to edits. The key, the journal and its exports
  are readable by their owner only: mode 0600, and on Windows an access list holding the person alone (`icacls`). The
  key is so from its first byte, in a shared folder too: it is written in a folder of its own, closed to everyone else
  before the key is in it (a new file takes its folder's access list on Windows), and only then put in place. A
  key file the person owns is set back to 0600 at every use; one another user owns that others can read is named by
  `journal`, with the fix.
- **A journal from 0.1.3 or earlier** held sha256 fingerprints without a key, which trying every number of an ID's
  range undoes. The first pass of 0.1.4 signs them again under the key of each record's folder and keeps them apart as
  `legacy_fingerprints`: repeats before the move are counted among themselves, never mixed with the new ones, and the
  unkeyed digests are no longer in the journal. A record holding a kind its folder keeps only as a count, or whose key
  cannot be used, keeps no fingerprint at all; a line an older gatecall still installed adds later is signed at the
  next pass.

## What it needs

Python 3.8+ and its standard library — no dependencies, no network module. Hooks and skills run through
`hooks/python.sh` (PowerShell: `hooks/python.ps1`), which finds a real Python and never starts the Apple or
Microsoft Store stub; with no Python the session start says so in one line.

## Checks

`python3 -m pytest -q tests` — every recognizer finds its valid example and lets the same number with one wrong
digit pass; the hooks stop and allow exactly as described, in the person's language; the journal holds no stopped
value — trying all 10,000 numbers of an ID range finds the one behind a 0.1.3 fingerprint and nothing behind a
0.1.4 one without the company's key, an ID number kept as a count leaves no fingerprint (one moved to a count later
loses the fingerprints it had), the key file is the owner's only from its first byte and never committed, records
past the retention period are gone, and 0.1.3 fingerprints come back signed and apart; each record keeps to its own
folder's policy and its session's `$COMPANY_AI_POLICY` from any folder and session, one with a policy of its own too;
four hooks and two passes writing at once lose no stop; a stop never rewrites the journal in its hook; no model step
opens the journal or the key, and the key is taken out of any output that reached it; `scan --json` names its key
and never makes one; the program rules hold; the permissions block uses absolute paths; no network code is present.
`python3 tools/mutate_code.py` breaks the rules one by one in a copy and expects the tests to go red; its last line
counts the mutations that misbehaved.

## Licence

Apache-2.0. See `LICENSE` and `NOTICE` (the recognizers follow Presidio's, MIT).
