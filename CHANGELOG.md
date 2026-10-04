# Changelog

## 0.1.4 — 2026-10-03

- Journal fingerprints are HMAC-SHA256 under the company's own key. In 0.1.0–0.1.3 they were sha256 without a
  key, and "the journal never holds a value" was not exact: trying every number of an ID's range against such a
  fingerprint finds the number. Without the key that search finds nothing now (a test runs it both ways).
- The key: 64 hex characters (32 random bytes from Python's `secrets`) in `journal.key` beside the journal, used as
  they stand as the HMAC key, made the first time a value is fingerprinted, readable by its owner only (0600; on
  Windows an access list holding the person alone, by `icacls`) from its first byte — it is written in a folder of
  its own, closed to everyone else before the key is in it, then put in place — and never replaced.
  `journal_key_file` in the policy (a relative path is read from the policy file's folder), or `$GATECALL_KEY_FILE`,
  names another file — one key on every laptop makes their journals comparable. Every record names the key its
  fingerprints were made with (`key_id`), so fingerprints under two keys are never compared. A key file the person
  owns is set back to 0600 at every use, and one inside a git work tree is listed in the repository's own
  `.git/info/exclude`, so it is never committed. README shows how the security team checks a number with `openssl`.
- A fingerprint is taken over the value as gatecall reads it: an ID number without spaces, dots or dashes, in
  capitals (12345678-Z and 12345678Z are one number), and a list of addresses or phone numbers over the list itself,
  so two different lists of the same length are two values.
- `journal_count_only` (e.g. `["national-id"]`): those kinds are kept only as a count, with no fingerprint; `true`
  keeps every kind so, and no key is made. It holds for the records already kept too: a kind moved to a count loses
  the fingerprints its records had at the next pass (a stop under the new rule starts one), and is never shown or
  exported with them.
- `journal_retention_days` (90 by default): each record is kept by the policy of the folder it was written in —
  its period, its count-only kinds, its key — whichever folder the journal is tended or read from, and carries
  `keep_until` for a folder no policy covers any more. A record written under `$COMPANY_AI_POLICY` names it
  (`company_ai_policy`) and is kept by it in a session that has no such variable, or another one; a 0.1.3 record
  takes the variable of the session that signs it again. A record past its period is deleted by a pass that runs
  in the background at every session start and whenever a stop finds one due, and before `journal` shows or exports
  anything; it is never shown or exported. A stop only adds its line: no hook waits on a pass.
- The company policy is looked for in the folders above the project too: a policy in the company folder holds in
  every folder inside it.
- `journal --export FILE [--format jsonl|csv] [--days N]`: every kept record (or those of the last N days) for the
  company's security team; a CSV cell a spreadsheet would run as a formula stays text. `journal` counts the values
  stopped more than once, and a stop whose kind is also its rule counts once (it counted twice).
- Migration: a journal from 0.1.3 or earlier is rewritten at the first pass — its fingerprints signed again under the
  key of each record's folder and kept as `legacy_fingerprints`, counted apart from the new ones; the unkeyed digests
  are no longer in the journal. A record holding a kind its folder keeps only as a count, or whose key cannot be used,
  keeps no fingerprint; a line an older gatecall still installed adds later is signed at the next pass.
- The journal and its exports are readable by their owner only. Hooks running at once take turns on the journal under
  the kernel's lock (`flock`; a locked byte on Windows), which is gone with a hook that is killed; a stop that cannot
  have it within 2 seconds is written to `journal.pending/` and joins the journal once. Files are opened in binary
  mode, so Windows adds no blank lines to the journal or the CSV. A journal that is there and cannot be read is said
  so by `journal`, never shown as empty.
- No model step opens the journal or its key, in any window, a Bash or a PowerShell command included. A step that
  reaches the key without naming it (a search over a folder that holds it, a script) has the key taken out of its
  output before Claude reads it — a new PostToolUse hook, Claude Code 2.1.227 or later — and the stop is journaled.
  The `settings` block adds Read and Edit of the key and Edit of gatecall's folder.
- `scan --json` gives each value's fingerprint under the same key with that key's `key_id`, so a stop in the journal
  can be matched to its file; it reads the key and never makes one, and where a value has no fingerprint it says why
  (no key on this computer, or a kind the company keeps only as a count).

## 0.1.3 — 2026-10-03

- Wording: no disclaimers. README and SECURITY.md say what gatecall does and where it reaches; the guard's
  rules, profiles and red folders are unchanged.
- Tests: a tone check reddens on disclaimers, excuses and apologies in what people read (five languages).

## 0.1.2 — 2026-10-03

- README: the Zenodo DOI badge (the concept DOI always points to the latest version).

## 0.1.1 — 2026-10-03

- Zenodo DOI: the repository is archived on Zenodo; this release is the first one it records (same content as 0.1.0).

## 0.1.0 — 2026-10-02

- First release: three hooks (session start, before a message, before a step), the skill, and the commands
  `scan`, `settings`, `route`, `copy`, `mark`, `journal`, `profiles`.
- Recognizers: keys and tokens of the main vendors, payment cards (Luhn), IBANs (ISO 13616 mod-97), twelve national
  ID numbers with their check digits, lists of e-mail addresses and phone numbers.
- Profiles `default`, `eu`, `us-federal-contractor`, `us-dod-strict`; program rules for kimi, grok and agy.
- `deny_jurisdictions` and `deny_providers` in the company policy: a hosts table in `data/profiles.json` names
  each model API host's vendor, country and source page; a denied country closes its hosts and keeps the same
  vendor's hosts elsewhere open (dashscope-intl in Singapore inside aliyuncs.com); a denied vendor closes its hosts
  and model names.
- `us-federal-contractor` cites FY2026 NDAA section 1532 from the Congressional Research Service summary.
- Messages in English, Spanish, Portuguese, Russian and Ukrainian.
- The red window: red folders open only to a session on this computer that carries routecall's local-red mark
  (`ROUTECALL_WINDOW=local-red`) with no Ollama cloud model behind the local address; in it no web tool and no
  network program to an outside host runs. An ordinary local window keeps them shut.
- `copy` masks keys, cards, IBANs, ID numbers and lists of people inside every file it copies (office documents
  part by part), and leaves out what cannot be read as text, named with the reason. A card right after a CSV
  field's comma is found.
