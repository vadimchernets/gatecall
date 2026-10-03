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
| Hooks | Before a message leaves: keys and tokens, card numbers (Luhn-checked), IBANs (mod-97), national ID numbers with their check digit (US, UK, Spain, Portugal, Brazil, France, Italy, Germany, the Netherlands, Poland, Ukraine, Russia), and lists of e-mail addresses or phone numbers stop it, with the reason in the person's language. Before a step: the same for commands, web requests and tool calls; red folders are read only in the red window — a model on this computer with routecall's `profile local-red` mark (`ROUTECALL_WINDOW=local-red`), where no web tool and no network program to an outside host runs; every other session, an ordinary local one included, is kept out of them. |
| Profiles | `default`, `eu` (every EU country's ID numbers; a list counts from three), `us-federal-contractor` (no DeepSeek model, API or weights; no API of Zhipu, which is on the US Entity List - its open GLM weights still run here), `us-dod-strict` (the wider list a contract may ask for). They add up. |
| Programs | kimi works only in a training folder of practice files; grok only on a cleaned copy (`copy`: no red folder, no key file, no `.git`; inside every file — office documents too — keys, cards, IBANs, ID numbers and lists of people are masked as `[card ********7899]`, and what cannot be read as text, such as a PDF or an image, stays out and is named with the reason); agy never gets a permission for everything. |
| Countries and vendors | `deny_jurisdictions` in the policy closes every model API host that processes data in those countries (a Singapore host of the same vendor stays open; weights on this computer still run); `deny_providers` closes a vendor's hosts and model names. The hosts table in `data/profiles.json` names each host's vendor, country and source page. |
| `settings` | The `permissions.deny` block for Claude Code: Read and Edit of every red folder by its absolute `//path`, and WebFetch of the hosts a profile denies. |
| `route` | Where red, yellow and green data go, from the company's policy. |
| `scan` | What in a file would be stopped, masked. |
| `journal` | What was stopped, by kind and rule — never the value. |

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
`copy_folders`, `markers`, `journal` and `fail_closed` (true: a message or a step the guard itself could not
check is stopped; by default the session goes on and the failure is journaled). It is looked for in this order: the managed copy an administrator
installed (`/Library/Application Support/ClaudeCode/`, `/etc/claude-code/`, `C:\Program Files\ClaudeCode\`), then
`$COMPANY_AI_POLICY`, then the project folder and its `.claude/`, then `~/.claude/`.

## What it needs

Python 3.8+ and its standard library — no dependencies, no network module. Hooks and skills run through
`hooks/python.sh` (PowerShell: `hooks/python.ps1`), which finds a real Python and never starts the Apple or
Microsoft Store stub; with no Python the session start says so in one line.

## Checks

`python3 -m pytest -q tests` — every recognizer finds its valid example and lets the same number with one wrong
digit pass; the hooks stop and allow exactly as described, in the person's language; the journal never holds a
value; the program rules hold; the permissions block uses absolute paths; no network code is present.
`python3 tools/mutate_code.py` breaks the rules one by one in a copy and expects the tests to go red; its last line
counts the mutations that misbehaved.

## Licence

Apache-2.0. See `LICENSE` and `NOTICE` (the recognizers follow Presidio's, MIT).
