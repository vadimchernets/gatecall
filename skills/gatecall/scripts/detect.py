#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gatecall's recognizers: what in a text must not leave the company.

Each recognizer checks what can be checked, so a random run of digits is not taken for a card or an ID:
the Luhn digit of a payment card, the ISO 13616 mod-97 of an IBAN, each national ID number's own check
digit. The shapes of keys and tokens are the public formats of each vendor, the way gitleaks (MIT) and
Presidio (MIT, now github.com/data-privacy-stack/presidio) list them; the code here is written anew.

A finding never carries the value itself: only its kind, a masked sample (the last four characters) and, when the
caller gives the company's key, a fingerprint - HMAC-SHA256 under that key - so the journal can count repeats
without keeping what it counted. Without the key a fingerprint cannot be traced back to its value, not even by
trying every possible number; with no key, no fingerprint is made at all. A value is fingerprinted the way it is
read, so one value written two ways is one fingerprint: a card's digits, an IBAN without spaces, an ID number
without spaces, dots or dashes in capitals, a key as written; a list of addresses or phone numbers is the list
itself - its addresses in lower case, or its numbers' digits, sorted, one a line - so two different lists of the
same length are two values, the same list in any order one.
Standard library only.
"""
import hashlib
import hmac
import re

KINDS = ("secret", "card", "iban", "national-id", "email-batch", "phone-batch")
FINGERPRINT_HEX = 16


def fingerprint(value, key):
    """HMAC-SHA256 (RFC 2104) of a value under the company's own key, its first 16 hex characters; None without a
    key. `key` is the key's bytes, or a function that gives them (or None) when the first fingerprint is needed."""
    if callable(key):
        key = key()
    if not key:
        return None
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:FINGERPRINT_HEX]


def mask(value, keep=4):
    clean = re.sub(r"\s", "", value)
    if len(clean) <= keep:
        return "*" * len(clean)
    return "*" * min(len(clean) - keep, 8) + clean[-keep:]


def finding(kind, name, value, span, count=1, key=None, mark=None):
    """`mark`: what is fingerprinted, when it is not the value as found."""
    return {"kind": kind, "name": name, "sample": mask(value),
            "fingerprint": fingerprint(value if mark is None else mark, key), "span": [span[0], span[1]], "count": count}


def overlaps(span, spans):
    return any(span[0] < other[1] and other[0] < span[1] for other in spans)


# ---------------------------------------------------------------- payment cards --------------

# Not right after a digit, a dot or a digit's comma (a decimal 3,14159...): a comma that ends a word or a field
# (Ana,4000 0012 3456 7899 in a CSV row) is a column's edge, and the card after it is found.
CARD_RE = re.compile(r"(?<![\d.])(?<!\d,)(?:\d[ -]?){12,18}\d(?!\d)")
# A cleaned copy also looks right after another number's comma (17,4000... - an id column, then the card);
# a decimal with a dozen digits after its comma could be masked with them, which a copy can afford.
CARD_FIELD_RE = re.compile(r"(?<![\d.])(?:\d[ -]?){12,18}\d(?!\d)")
# The first digits the card networks issue: Visa 4, Mastercard 51-55 and 2221-2720, Amex 34/37,
# Diners 30/36/38/39, Discover, UnionPay, Maestro and JCB in 6 and 35.
CARD_PREFIX = re.compile(r"^(?:4|5[1-5]|2[2-7]|3[0-9]|6)")


def luhn_ok(digits):
    """The Luhn check digit (ISO/IEC 7812): every second digit from the right doubled, the sum ends in 0."""
    if not digits or not digits.isdigit():
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def cards(text, skip=(), pattern=CARD_RE, key=None):
    out = []
    for m in pattern.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if not 13 <= len(digits) <= 19 or not CARD_PREFIX.match(digits) or len(set(digits)) == 1:
            continue
        if overlaps(m.span(), skip):
            continue                        # the digits of an IBAN already found are not a card
        if luhn_ok(digits):
            out.append(finding("card", "payment card", digits, m.span(), key=key))
    return out


# ---------------------------------------------------------------- IBAN ------------------------

IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,32}")
# The lengths of the most used countries (ISO 13616 registry); any other country: 15 to 34 characters.
IBAN_LENGTHS = {"AT": 20, "BE": 16, "BG": 22, "BR": 29, "CH": 21, "CZ": 24, "DE": 22, "DK": 18, "EE": 20,
                "ES": 24, "FI": 18, "FR": 27, "GB": 22, "GR": 27, "HR": 21, "HU": 28, "IE": 22, "IT": 27,
                "LT": 20, "LU": 20, "LV": 21, "NL": 18, "NO": 15, "PL": 28, "PT": 25, "RO": 24, "SE": 24,
                "SI": 19, "SK": 24, "TR": 26, "UA": 29}


def iban_ok(value):
    """ISO 13616: the first four characters moved to the end, letters turned into 10..35, the number
    divided by 97 leaves 1."""
    if not re.match(r"^[A-Z]{2}\d{2}[A-Z0-9]+$", value) or not 15 <= len(value) <= 34:
        return False
    moved = value[4:] + value[:4]
    digits = "".join(str(int(ch, 36)) for ch in moved)
    return int(digits) % 97 == 1


def ibans(text, key=None):
    out = []
    for m in IBAN_RE.finditer(text):
        flat = m.group(0).replace(" ", "")
        lengths = [IBAN_LENGTHS[flat[:2]]] if flat[:2] in IBAN_LENGTHS else range(min(len(flat), 34), 14, -1)
        for length in lengths:
            candidate = flat[:length]
            if len(candidate) == length and iban_ok(candidate):
                out.append(finding("iban", "bank account (IBAN)", candidate, m.span(), key=key))
                break
    return out


# ---------------------------------------------------------------- keys and tokens -------------

SECRETS = (
    ("private key", re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("OpenRouter API key", re.compile(r"\bsk-or-v1-[A-Za-z0-9]{32,}")),
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}")),
    ("Google OAuth client secret", re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{20,}")),
    ("Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("Stripe live key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}")),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{30,}")),
    ("Groq API key", re.compile(r"\bgsk_[A-Za-z0-9]{40,}")),
    ("xAI API key", re.compile(r"\bxai-[A-Za-z0-9]{40,}")),
    ("JSON web token", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
)


def secrets(text, key=None):
    out = []
    taken = []
    for name, pattern in SECRETS:
        for m in pattern.finditer(text):
            if overlaps(m.span(), taken):
                continue
            taken.append(m.span())
            out.append(finding("secret", name, m.group(0), m.span(), key=key))
    return out


# ---------------------------------------------------------------- lists of people -------------

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"(?<![\w+])\+?\d[\d ().-]{6,20}\d(?!\w)")
NOT_PHONE = (re.compile(r"^\d{4}[-./]\d{1,2}[-./]\d{1,2}"),       # a date, 2026-10-02 ...
             re.compile(r"^\d{1,2}[-./]\d{1,2}[-./]\d{2,4}"),     # a date, 02.10.2026 ...
             re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}"))             # an IP address or a version


def emails(text):
    found = {}
    for m in EMAIL_RE.finditer(text):
        found.setdefault(m.group(0).lower(), m.span())
    return found


def phone_spans(text, skip=()):
    """Every phone number in a text, each time it appears: (its digits, its span)."""
    out = []
    for m in PHONE_RE.finditer(text):
        raw = m.group(0)
        digits = re.sub(r"\D", "", raw)
        if not 9 <= len(digits) <= 15 or overlaps(m.span(), skip):
            continue
        if not raw.startswith("+") and not re.search(r"[ ().-]", raw):
            continue                        # a bare run of digits is an order number, not a phone
        if any(p.match(raw) for p in NOT_PHONE):
            continue
        out.append((digits, m.span()))
    return out


def phones(text, skip=()):
    found = {}
    for digits, span in phone_spans(text, skip):
        found.setdefault(digits, span)
    return found


# ---------------------------------------------------------------- national ID numbers ---------

def _digits(value):
    return [ord(ch) - 48 for ch in value]


def us_ssn(m):
    area, group, serial = m.group(1), m.group(2), m.group(3)
    return not (area in ("000", "666") or area.startswith("9") or group == "00" or serial == "0000")


GB_NINO_BAD = ("BG", "GB", "NK", "KN", "TN", "NT", "ZZ")


def gb_nino(m):
    return m.group(1) not in GB_NINO_BAD


DNI_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"


def es_dni(m):
    body = m.group(1)
    if body[0] in "XYZ":
        body = str("XYZ".index(body[0])) + body[1:]
    return DNI_LETTERS[int(body) % 23] == m.group(2)


def pt_nif(m):
    d = _digits(m.group(1))
    if d[0] not in (1, 2, 3, 5, 6, 8, 9):
        return False
    rest = sum(d[i] * (9 - i) for i in range(8)) % 11
    return d[8] == (0 if rest < 2 else 11 - rest)


def br_cpf(m):
    d = _digits("".join(m.groups()))
    if len(set(d)) == 1:
        return False
    for size in (9, 10):
        rest = sum(d[i] * (size + 1 - i) for i in range(size)) % 11
        if d[size] != (0 if rest < 2 else 11 - rest):
            return False
    return True


def fr_nir(m):
    flat = re.sub(r"\s", "", m.group(0))
    body = flat[:13].replace("2A", "19").replace("2B", "18")
    return int(flat[13:]) == 97 - int(body) % 97


IT_ODD = dict(zip("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                  (1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3,
                   6, 8, 12, 14, 16, 10, 22, 25, 24, 23)))


def it_cf(m):
    code = m.group(0)
    total = 0
    for i, ch in enumerate(code[:15]):
        if i % 2 == 0:
            total += IT_ODD[ch]
        else:
            total += int(ch) if ch.isdigit() else ord(ch) - 65
    return chr(65 + total % 26) == code[15]


def de_steuer_id(m):
    d = _digits(m.group(1))
    if d[0] == 0:
        return False
    product = 10
    for digit in d[:10]:
        total = (digit + product) % 10
        if total == 0:
            total = 10
        product = (total * 2) % 11
    check = 11 - product
    return d[10] == (0 if check == 10 else check)


def nl_bsn(m):
    d = _digits(m.group(1))
    return (sum(d[i] * (9 - i) for i in range(8)) - d[8]) % 11 == 0 and any(d)


def pl_pesel(m):
    d = _digits(m.group(1))
    weights = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
    return d[10] == (10 - sum(w * x for w, x in zip(weights, d)) % 10) % 10


def ua_rnokpp(m):
    d = _digits(m.group(1))
    weights = (-1, 5, 7, 9, 4, 6, 10, 5, 7)
    return d[9] == (sum(w * x for w, x in zip(weights, d)) % 11) % 10


def ru_inn(m):
    d = _digits(m.group(1))

    def check(weights):
        return sum(w * x for w, x in zip(weights, d)) % 11 % 10

    if len(d) == 10:
        return d[9] == check((2, 4, 10, 3, 5, 9, 4, 6, 8))
    return (d[10] == check((7, 2, 4, 10, 3, 5, 9, 4, 6, 8))
            and d[11] == check((3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8)))


# id -> (pattern, check). Their names, countries and context words live in data/profiles.json.
NATIONAL_IDS = {
    "us-ssn": (re.compile(r"\b(\d{3})-(\d{2})-(\d{4})\b"), us_ssn),
    "gb-nino": (re.compile(r"\b([A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]) ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b"), gb_nino),
    "es-dni": (re.compile(r"\b([XYZ]\d{7}|\d{8})-?([A-Z])\b"), es_dni),
    "pt-nif": (re.compile(r"(?<!\d)(\d{9})(?!\d)"), pt_nif),
    "br-cpf": (re.compile(r"(?<!\d)(\d{3})\.?(\d{3})\.?(\d{3})-?(\d{2})(?!\d)"), br_cpf),
    "fr-nir": (re.compile(r"(?<!\d)[12] ?\d{2} ?(?:0[1-9]|1[0-2]|[2-9]\d) ?(?:\d{2}|2A|2B) ?\d{3} ?\d{3} ?\d{2}(?!\d)"),
               fr_nir),
    "it-cf": (re.compile(r"\b[A-Z]{6}\d{2}[ABCDEHLMPRST]\d{2}[A-Z]\d{3}[A-Z]\b"), it_cf),
    "de-steuer-id": (re.compile(r"(?<!\d)(\d{11})(?!\d)"), de_steuer_id),
    "nl-bsn": (re.compile(r"(?<!\d)(\d{9})(?!\d)"), nl_bsn),
    "pl-pesel": (re.compile(r"(?<!\d)(\d{11})(?!\d)"), pl_pesel),
    "ua-rnokpp": (re.compile(r"(?<!\d)(\d{10})(?!\d)"), ua_rnokpp),
    "ru-inn": (re.compile(r"(?<!\d)(\d{12}|\d{10})(?!\d)"), ru_inn),
}


def id_mark(value):
    """An ID number as it is fingerprinted: without spaces, dots or dashes, in capitals - 12345678-Z and 12345678Z,
    111.444.777-35 and 11144477735 are one number."""
    return re.sub(r"[\s.\-]", "", value).upper()


def has_context(text, span, words):
    if not words:
        return True
    window = text[max(0, span[0] - 60):span[1] + 60].lower()
    return any(word.lower() in window for word in words)


def national_ids(text, ids, catalogue, skip=(), key=None):
    """ids: the ID kinds to look for; catalogue: data/profiles.json's national_ids (name, context words)."""
    out = []
    for kind in ids:
        pattern, check = NATIONAL_IDS[kind]
        info = catalogue.get(kind, {})
        for m in pattern.finditer(text):
            if overlaps(m.span(), skip) or not has_context(text, m.span(), info.get("context") or []):
                continue
            try:
                ok = check(m)
            except (ValueError, KeyError, IndexError):
                ok = False
            if ok:
                out.append(finding("national-id", info.get("name", kind), m.group(0), m.span(), key=key,
                                   mark=id_mark(m.group(0))))
    return out


# ---------------------------------------------------------------- one text --------------------

def scan(text, ids=(), catalogue=None, email_batch=5, phone_batch=5, key=None):
    """Every finding in one text. A list of addresses or phone numbers counts from its threshold on:
    one address in a letter is work, a column of them is a list of people. `key`: the company's journal key (or
    the function that gives it), for the findings' fingerprints; without it they carry none."""
    if not isinstance(text, str) or not text:
        return []
    out = secrets(text, key) + ibans(text, key)
    out.extend(cards(text, skip=[f["span"] for f in out], key=key))
    taken = [f["span"] for f in out]
    out.extend(national_ids(text, ids, catalogue or {}, skip=taken, key=key))
    taken = [f["span"] for f in out]
    addresses = emails(text)
    if email_batch and len(addresses) >= email_batch:
        first = min(addresses.values())
        out.append(finding("email-batch", "a list of e-mail addresses", "%d addresses" % len(addresses), first,
                           count=len(addresses), key=key, mark="\n".join(sorted(addresses))))
        out[-1]["sample"] = "%d addresses" % len(addresses)
    numbers = phones(text, skip=taken + [list(s) for s in addresses.values()])
    if phone_batch and len(numbers) >= phone_batch:
        first = min(numbers.values())
        out.append(finding("phone-batch", "a list of phone numbers", "%d numbers" % len(numbers), first,
                           count=len(numbers), key=key, mark="\n".join(sorted(numbers))))
        out[-1]["sample"] = "%d numbers" % len(numbers)
    return out
