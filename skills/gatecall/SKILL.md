---
name: gatecall
description: Decide with a company which of its data may go to which AI, and keep to it - red folders stay with a model on this computer, and keys, card numbers, IBANs, ID numbers and lists of people's addresses or phone numbers are stopped before they leave in a message, a command or a tool call. Use it when someone from a company asks what they may give to an AI, wants client or staff files kept private, works for an EU company or a US defence contractor, wants another AI agent (kimi, grok, agy) to work on their files, or asks what the guard stopped.
argument-hint: "[setup | route | scan | settings | copy | journal] [what]"
allowed-tools: Bash(sh "${CLAUDE_PLUGIN_ROOT}/hooks/python.sh" gatecall say skills/gatecall/scripts/gatecall.py *) PowerShell(${CLAUDE_PLUGIN_ROOT}/hooks/python.ps1 gatecall say skills/gatecall/scripts/gatecall.py *) Read Write
---

# gatecall: what may leave the company, and where it may go

## Running gatecall's scripts (Mac, Linux, Windows)

Every script command on this page is written for the **Bash** tool and starts with
`sh "${CLAUDE_PLUGIN_ROOT}/hooks/python.sh" gatecall say skills/gatecall/scripts/…`. If your shell tool is
**PowerShell** (Windows without Git Bash), only the start changes: write the launcher's path bare, with no quotes
and no `&` — `${CLAUDE_PLUGIN_ROOT}/hooks/python.ps1 gatecall say skills/gatecall/scripts/…` — and keep the rest,
on one line; that is the form this skill's permission covers. Only if that path has a space in it, write
`& "${CLAUDE_PLUGIN_ROOT}/hooks/python.ps1" …` instead (the person is then asked once). Never call `python3`,
`python` or `py` yourself: the launcher finds a real Python 3.8+ and never starts the Microsoft Store or Apple
stub. If it answers with one line saying gatecall "is paused" because this computer has no working Python 3 yet,
tell the person that in one plain line: until step 0 is done the guard is off, so red folders are not opened in
this session at all.

The user said: $ARGUMENTS

Answer in the person's language, plainly. gatecall gives the company working routes for every kind of data — it
says where a thing *can* go, never only where it cannot.

## 1. Setting it up with the company (setup)

Ask, one at a time:

1. Which folders hold what must never leave the company — client files, staff files, contracts, health or bank
   records? These are **red**: the red window reads them — a model on this computer, opened with routecall's
   `profile local-red`; every other window, an ordinary local one included, keeps them shut.
2. Which folders are work that may go to the company's own accounts — **yellow**: Claude Team or Enterprise seats
   (the company owns the outputs) or an API with zero data retention.
3. The country, and whether the company is in the EU or works under a US defence contract.
4. Whether some countries or vendors are out for the company's data (a client contract, a tender, a board
   decision). Write them as `deny_jurisdictions` (country codes, e.g. `["CN"]`: the API hosts that process data
   there are closed, the same vendor's hosts elsewhere stay open, and open weights on this computer still run) or
   `deny_providers` (vendor names as in billcall's price table: their hosts and their model names are closed).
   Most companies leave both empty and route by the colour of the data instead.

Write `company-ai-policy.json` in the company folder (the shape is in
`${CLAUDE_PLUGIN_ROOT}/data/company-ai-policy.example.json`; firmcall installs the same file as managed settings for
every laptop later):

```json
{"schema": 1, "country": "ES", "language": "es", "profiles": ["default", "eu"],
 "red_paths": ["~/Company/Clients"], "yellow_paths": ["~/Company/Projects"], "training_folders": []}
```

Profiles: `default` (any company), `eu` (every EU country's ID numbers; a list counts from three),
`us-federal-contractor` (no DeepSeek model, API or weights; no API of Zhipu, which is on the US Entity List - its open GLM weights still run here), `us-dod-strict` (only when the contract asks for the
wider list). Then show where everything goes:

```
sh "${CLAUDE_PLUGIN_ROOT}/hooks/python.sh" gatecall say skills/gatecall/scripts/gatecall.py route
```

and write the permissions block that closes red folders to the windows that talk to a cloud model:

```
sh "${CLAUDE_PLUGIN_ROOT}/hooks/python.sh" gatecall say skills/gatecall/scripts/gatecall.py settings --out "<folder>/gatecall-deny.json"
```

Its `permissions.deny` goes where only cloud sessions read it: the claude.ai console settings (firmcall writes them
as `server-managed-settings.json`; a session on api.anthropic.com fetches them, the red window never does), and the
`--settings` of every cloud window (routecall's cloud profiles already carry it). A deny rule wins over every other
level, so it never goes into a file the red window reads too — the project's `.claude/settings.json` or the
laptop's managed file: there the red window could not open the red folders either. On every laptop the red folders
are held by this plugin's own hook, which opens them only to the red window. The rules use absolute `//` paths, so
they hold from any folder.

## 2. When the guard stops something

The hooks stop a message or a step that carries a key, a card number, an IBAN, an ID number, or a list of
addresses or phone numbers, and say why in the person's language. Tell the person in one line what was found
(only the masked sample) and the two ways forward: take it out or mask it, or do the work on the company's own
model on this computer. Never retype the stopped value yourself.

To check a file before it goes anywhere:

```
sh "${CLAUDE_PLUGIN_ROOT}/hooks/python.sh" gatecall say skills/gatecall/scripts/gatecall.py scan "<file>"
```

## 3. Another AI agent on the company's files

- **kimi** works only in a training folder of practice files. A person marks one themselves, in their own
  terminal: `gatecall.py mark --training <folder>` (the guard does not let Claude mark it), or the company lists it
  in `training_folders`.
- **grok** works only on a cleaned copy:
  `sh "${CLAUDE_PLUGIN_ROOT}/hooks/python.sh" gatecall say skills/gatecall/scripts/gatecall.py copy "<folder>" "<new folder>"`
  copies everything except red folders, key files and `.git`; inside every file it copies (office documents
  too, part by part) it masks keys, card numbers, IBANs, ID numbers and lists of addresses or phone numbers, as
  `[card ********7899]`; what cannot be read as text (a PDF, an image) stays out and is named with the reason, so
  the person can save it as text and copy that. It marks the copy and lists what was masked where — kinds and
  counts, never the values.
- **agy** never gets a permission for everything; put the text inside the question instead.

## 4. What was stopped (journal)

```
sh "${CLAUDE_PLUGIN_ROOT}/hooks/python.sh" gatecall say skills/gatecall/scripts/gatecall.py journal --days 7
```

The journal keeps the kind, the rule and a fingerprint — never the value itself.
