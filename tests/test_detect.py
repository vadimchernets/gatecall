"""gatecall's recognizers: every valid example is found, and the same number with one wrong digit is not.

The red case and its green twin stand side by side, so a check that cannot fail shows up as a failing test.
Keys and tokens are built at run time from pieces: no file of this repository holds a string a secret scanner
would take for a real key.
"""
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("gatecall_detect", str(ROOT / "skills" / "gatecall" / "scripts" / "detect.py"))
detect = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(detect)
CATALOGUE = json.loads((ROOT / "data" / "profiles.json").read_text(encoding="utf-8"))["national_ids"]
ALL_IDS = sorted(detect.NATIONAL_IDS)


def kinds(text, **options):
    return [f["kind"] for f in detect.scan(text, **options)]


class Cards(unittest.TestCase):
    def test_luhn(self):
        self.assertTrue(detect.luhn_ok("4000001234567899"))
        self.assertFalse(detect.luhn_ok("4000001234567898"))
        self.assertTrue(detect.luhn_ok("79927398713"))          # the textbook Luhn example
        self.assertFalse(detect.luhn_ok("79927398710"))

    def test_a_card_in_a_sentence_is_found_and_masked(self):
        found = detect.scan("pay it with 4000 0012 3456 7899 today")
        self.assertEqual([f["kind"] for f in found], ["card"])
        self.assertTrue(found[0]["sample"].endswith("7899"))
        self.assertNotIn("4000001234567899", json.dumps(found))
        self.assertEqual(len(found[0]["fingerprint"]), 12)

    def test_the_same_number_with_a_wrong_last_digit_is_not_a_card(self):
        self.assertEqual(kinds("pay it with 4000 0012 3456 7898 today"), [])

    def test_a_long_run_of_digits_is_not_a_card(self):
        self.assertEqual(kinds("order 1234567890123456789012345"), [])


class Iban(unittest.TestCase):
    def test_valid_ibans_are_found_with_or_without_spaces(self):
        for text in ("GB82WEST12345698765432", "send to GB82 WEST 1234 5698 7654 32 PAID",
                     "IBAN: DE89 3704 0044 0532 0130 00"):
            self.assertEqual(kinds(text), ["iban"], text)

    def test_one_wrong_digit_and_it_is_not_an_iban(self):
        self.assertFalse(detect.iban_ok("GB82WEST12345698765433"))
        self.assertEqual(kinds("send to GB82 WEST 1234 5698 7654 33"), [])

    def test_the_digits_of_an_iban_are_not_taken_for_a_card(self):
        self.assertEqual(kinds("DE89 3704 0044 0532 0130 00"), ["iban"])


class Secrets(unittest.TestCase):
    def test_keys_and_tokens(self):
        samples = {
            "Anthropic API key": "sk-" + "ant-api03-" + "Ab1" * 12,
            "AWS access key": "AKIA" + "IOSFODNN7EXAMPLE",
            "GitHub token": "gh" + "p_" + "aB3" * 12,
            "private key": "-----BEGIN " + "OPENSSH PRIVATE KEY-----",
            "Google API key": "AI" + "za" + "Sy" + "A1b2C3d4E5" * 3 + "xyz",
        }
        for name, value in samples.items():
            found = detect.scan("here it is: %s and more" % value)
            self.assertEqual([(f["kind"], f["name"]) for f in found], [("secret", name)], name)
            self.assertNotIn(value, json.dumps(found))

    def test_ordinary_words_are_not_keys(self):
        self.assertEqual(kinds("the sk-short key, a skeleton, AKIA alone, ghp_ and nothing"), [])


class People(unittest.TestCase):
    def test_a_list_of_addresses_counts_from_its_threshold(self):
        five = "\n".join("person%d@acme.test" % i for i in range(5))
        four = "\n".join("person%d@acme.test" % i for i in range(4))
        self.assertEqual(kinds(five), ["email-batch"])
        self.assertEqual(kinds(four), [])
        self.assertEqual(kinds("a@x.test b@x.test c@x.test", email_batch=3), ["email-batch"])
        found = detect.scan(five)
        self.assertEqual((found[0]["count"], found[0]["sample"]), (5, "5 addresses"))

    def test_a_list_of_phone_numbers_counts_from_its_threshold(self):
        numbers = ["+44 20 7946 0958", "+1 (415) 555-0100", "+49 30 901820", "+380 44 123 4567", "+33 1 40 20 50 50"]
        self.assertEqual(kinds("\n".join(numbers)), ["phone-batch"])
        self.assertEqual(kinds("\n".join(numbers[:4])), [])

    def test_dates_and_addresses_of_machines_are_not_phone_numbers(self):
        lines = ["2026-10-0%d 10:00 started" % d for d in range(1, 7)] + ["192.168.1.%d" % d for d in range(10, 16)]
        self.assertEqual(kinds("\n".join(lines)), [])


# (id, a valid example in context, the same with one wrong character)
IDS = (
    ("us-ssn", "SSN 536-22-4170", "SSN 000-22-4170"),
    ("gb-nino", "NI number AB123456C", "NI number GB123456C"),
    ("es-dni", "DNI 12345678Z", "DNI 12345678A"),
    ("pt-nif", "NIF 123456789", "NIF 123456788"),
    ("br-cpf", "CPF 111.444.777-35", "CPF 111.444.777-36"),
    ("fr-nir", "NIR 1 85 05 78 006 084 91", "NIR 1 85 05 78 006 084 92"),
    ("it-cf", "codice fiscale RSSMRA85T10A562S", "codice fiscale RSSMRA85T10A562T"),
    ("de-steuer-id", "Steuer-ID 86095742719", "Steuer-ID 86095742718"),
    ("nl-bsn", "BSN 111222333", "BSN 111222334"),
    ("pl-pesel", "PESEL 44051401359", "PESEL 44051401358"),
    ("ua-rnokpp", "RNOKPP 3012415678", "RNOKPP 3012415679"),
    ("ru-inn", "INN 7707083893", "INN 7707083894"),
    ("ru-inn", "INN 500100732259", "INN 500100732258"),
)


class NationalIds(unittest.TestCase):
    def ids_in(self, text):
        return [f["name"] for f in detect.scan(text, ids=ALL_IDS, catalogue=CATALOGUE) if f["kind"] == "national-id"]

    def test_every_check_digit(self):
        for key, good, bad in IDS:
            self.assertEqual(self.ids_in(good), [CATALOGUE[key]["name"]], good)
            self.assertEqual(self.ids_in(bad), [], bad)

    def test_a_number_that_needs_its_word_is_not_taken_without_it(self):
        self.assertEqual(self.ids_in("order 123456789 shipped"), [])
        self.assertEqual(self.ids_in("NIF 123456789"), [CATALOGUE["pt-nif"]["name"]])

    def test_only_the_kinds_asked_for_are_looked_for(self):
        self.assertEqual([f["kind"] for f in detect.scan("SSN 536-22-4170", ids=[], catalogue=CATALOGUE)], [])


if __name__ == "__main__":
    unittest.main()
