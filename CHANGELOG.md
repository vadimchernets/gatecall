# Changelog

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
