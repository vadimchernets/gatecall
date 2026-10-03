#!/usr/bin/env python3
"""Break gatecall's own rules on purpose, in a copy, and watch the tests redden.

Each mutation copies the plugin folder to a temporary place, changes one exact text in one file of the
copy (the text must be there exactly once, or the mutation itself is reported as broken), runs the named
tests in the copy, and expects them red. The control mutation changes a comment and expects green. After
every run the sha256 of every original file is compared with the one taken at the start: the plugin itself
is never touched. The last line counts the mutations that misbehaved; anything but 0 is a failure.

  python3 tools/mutate_code.py            (about a minute; needs pytest, like the tests themselves)
"""
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DETECT = "skills/gatecall/scripts/detect.py"
GATECALL = "skills/gatecall/scripts/gatecall.py"
PROFILES = "data/profiles.json"
SKIP = (".git", "__pycache__", ".pytest_cache", "dist")

# (what is broken, file, exact text, replacement, tests to run, expected outcome)
MUTATIONS = (
    ("control: a comment reworded", DETECT,
     "# a bare run of digits is an order number, not a phone", "# a bare run of digits is not a phone number",
     "tests/test_detect.py", "green"),
    ("the Luhn check removed: any 16 digits are a card", DETECT,
     "        if luhn_ok(digits):", "        if True:",
     "tests/test_detect.py::Cards", "red"),
    ("the IBAN mod-97 removed", DETECT,
     "return int(digits) % 97 == 1", "return True",
     "tests/test_detect.py::Iban", "red"),
    ("a national ID's check digit removed (PESEL)", DETECT,
     "return d[10] == (10 - sum(w * x for w, x in zip(weights, d)) % 10) % 10", "return True",
     "tests/test_detect.py::NationalIds", "red"),
    ("DeepSeek no longer denied to a US defence contractor", PROFILES,
     '"deny_models": ["deepseek"],', '"deny_models": [],',
     "tests/test_gatecall.py::Company::test_a_defence_contractor_runs_no_deepseek_and_any_company_may", "red"),
    ("a host in a denied jurisdiction passes", GATECALL,
     'elif str(entry.get("jurisdiction", "")).upper() in places:', "elif False:",
     "tests/test_gatecall.py::Company::test_a_denied_jurisdiction_closes_its_hosts_and_keeps_the_rest", "red"),
    ("a Singapore host inside a denied Chinese domain is closed too", GATECALL,
     'if any(host_matches(host, keep) for keep in rules.get("keep_hosts") or ()):', "if False:",
     "tests/test_gatecall.py::Company::test_a_denied_jurisdiction_closes_its_hosts_and_keeps_the_rest", "red"),
    ("a denied provider's models still run", GATECALL,
     'deny_models |= set(entry.get("models") or [])', "pass",
     "tests/test_gatecall.py::Company::test_a_denied_provider_closes_its_hosts_and_its_models", "red"),
    ("Kimi gets the company's real folder", GATECALL,
     'if rule == "training-only":', "if False:",
     "tests/test_gatecall.py::Company::test_kimi_works_only_in_a_training_folder", "red"),
    ("a message is never checked", GATECALL,
     'findings = [] if route["local"] else findings_in(payload.get("prompt") or "", rules)', "findings = []",
     "tests/test_gatecall.py::Company::test_a_card_in_a_message_is_stopped_masked_and_journaled_without_the_number", "red"),
    ("a red folder is read by a cloud model", GATECALL,
     "            if under(path, red):", "            if False:",
     "tests/test_gatecall.py::Company::test_a_red_folder_is_read_only_by_the_red_window", "red"),
    ("an ordinary local window opens the red folders", GATECALL,
     'str(env.get(WINDOW_VAR) or "") == RED_WINDOW', "True",
     "tests/test_gatecall.py::Company::test_a_red_folder_is_read_only_by_the_red_window", "red"),
    ("the red window reaches the web", GATECALL,
     'far = [tool] if tool in OUTGOING_TOOLS else (outside_hosts(text, cwd) if tool == "Bash" else [])', "far = []",
     "tests/test_gatecall.py::Company::test_the_red_window_keeps_everything_on_this_computer", "red"),
    ("a cleaned copy carries a file's card", GATECALL,
     "    clean, found = mask_text(text, rules)\n    if not found:", "    clean, found = text, []\n    if not found:",
     "tests/test_gatecall.py::Company::test_a_copy_masks_what_must_not_leave_inside_the_files", "red"),
)


def digest(root):
    """sha256 of every file under root (junk folders left out), keyed by relative path."""
    out = {}
    for folder, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP)
        for name in names:
            path = os.path.join(folder, name)
            with open(path, "rb") as handle:
                out[os.path.relpath(path, root)] = hashlib.sha256(handle.read()).hexdigest()
    return out


def run_one(tmp, n, mutation):
    """-> ("red" | "green" | "error", detail)."""
    _name, rel, old, new, tests, _expect = mutation
    copy = os.path.join(tmp, "m%02d" % n)
    shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns(*SKIP))
    target = os.path.join(copy, rel)
    with open(target, encoding="utf-8") as handle:
        text = handle.read()
    if text.count(old) != 1:
        return "error", "%r is in %s %d times, not once" % (old, rel, text.count(old))
    with open(target, "w", encoding="utf-8") as handle:
        handle.write(text.replace(old, new, 1))
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    try:
        done = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", tests],
                              cwd=copy, env=env, capture_output=True, text=True, timeout=600)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "error", repr(exc)
    last = (done.stdout.strip().splitlines() or [""])[-1]
    if done.returncode == 0:
        return "green", last
    if done.returncode == 1:
        return "red", last
    return "error", "pytest exit %d: %s" % (done.returncode, (done.stdout + done.stderr).strip()[-300:])


def main():
    before = digest(ROOT)
    bad = 0
    tmp = tempfile.mkdtemp(prefix="gatecall-mutate-")
    try:
        for n, mutation in enumerate(MUTATIONS):
            name, expect = mutation[0], mutation[5]
            outcome, detail = run_one(tmp, n, mutation)
            if outcome == expect:
                print("ok   %s: %s as expected (%s)" % (name, expect, detail))
            else:
                print("BAD  %s: expected %s, got %s (%s)" % (name, expect, outcome, detail))
                bad += 1
            after = digest(ROOT)
            if after != before:
                print("BAD  the plugin's own files changed during '%s'" % name)
                bad += 1
                before = after
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("misbehaving: %d" % bad)
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
