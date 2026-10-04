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
PLUGIN_JSON = ".claude-plugin/plugin.json"
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
     'findings = [] if route["local"] else findings_in(payload.get("prompt") or "", rules, key)', "findings = []",
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
    # the journal (0.1.4): HMAC under the company's key, the key owner-only and never replaced, counts, retention,
    # the 0.1.3 fingerprints signed again and kept apart, one writer at a time, a spreadsheet-safe export
    ("the fingerprint without a key, as in 0.1.3", DETECT,
     'return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:FINGERPRINT_HEX]',
     'return hashlib.sha256(value.encode("utf-8")).hexdigest()[:FINGERPRINT_HEX]',
     "tests/test_detect.py::Fingerprints", "red"),
    ("the journal's key readable by everyone", GATECALL,
     "os.chmod(path, 0o700 if folder else 0o600)", "os.chmod(path, 0o700 if folder else 0o644)",
     "tests/test_gatecall.py::Company::test_the_journal_keeps_a_fingerprint_under_the_companys_own_key", "red"),
    ("a key already there is replaced", GATECALL,
     "            pass                            # another hook made it first: its key is the key",
     "            os.replace(tmp, path)",
     "tests/test_gatecall.py::Company::test_the_company_names_where_its_key_lives", "red"),
    ("ID numbers keep a fingerprint though the company asked for a count", GATECALL,
     'signed = [f for f in findings if f["kind"] not in counted_kinds]', "signed = list(findings)",
     "tests/test_gatecall.py::Company::test_id_numbers_may_be_kept_only_as_a_count", "red"),
    ("records past the retention period stay in the file", GATECALL,
     "        if until <= now:\n            changed = True", "        if False:\n            changed = True",
     "tests/test_gatecall.py::Company::test_records_older_than_the_retention_period_are_deleted_and_never_shown", "red"),
    ("a record past the retention period is shown and exported", GATECALL,
     "if expiry(record, when, policy, where) <= now:", "if False:",
     "tests/test_gatecall.py::Company::test_records_older_than_the_retention_period_are_deleted_and_never_shown", "red"),
    ("a 0.1.3 fingerprint mixed with the new ones", GATECALL,
     'out["legacy_fingerprints"] = sorted(', 'out["fingerprints"] = sorted(',
     "tests/test_gatecall.py::Company::test_a_journal_from_0_1_3_is_signed_again_and_kept_apart", "red"),
    ("a 0.1.3 fingerprint kept without the key", GATECALL,
     "set(detect.fingerprint(LEGACY + mark, key) for mark in old)", "set(old)",
     "tests/test_gatecall.py::Company::test_a_journal_from_0_1_3_is_signed_again_and_kept_apart", "red"),
    ("a 0.1.3 ID number's fingerprint signed though IDs are kept as a count", GATECALL,
     'if old and set(strings(record.get("kinds"))) & set(counted_kinds):', "if False:",
     "tests/test_gatecall.py::Company::test_a_0_1_3_fingerprint_of_a_kind_kept_as_a_count_is_dropped_not_signed", "red"),
    ("two writers of the journal at once: the lock never refuses", GATECALL,
     "            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)", "            pass",
     "tests/test_gatecall.py::Company::test_a_stop_never_waits_on_the_journal_and_its_line_is_never_lost", "red"),
    ("a stop written into the journal behind the lock's back", GATECALL,
     "        if not held:\n            write_pending(record)\n            return True\n", "",
     "tests/test_gatecall.py::Company::test_a_stop_never_waits_on_the_journal_and_its_line_is_never_lost", "red"),
    ("a line that waited aside joins the journal twice", GATECALL,
     'if record is not None and record.get("id") not in seen:', "if record is not None:",
     "tests/test_gatecall.py::Company::test_a_stop_never_waits_on_the_journal_and_its_line_is_never_lost", "red"),
    ("a lock that outlives a killed hook (a marker file, as before 0.1.4)", GATECALL,
     "            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)",
     "            os.close(os.open(home_file(LOCK_NAME) + '.held', os.O_WRONLY | os.O_CREAT | os.O_EXCL))",
     "tests/test_gatecall.py::Company::test_the_journals_lock_dies_with_the_hook_that_held_it", "red"),
    ("a pass puts its file in place without the journal's lock", GATECALL,
     "        with file_lock(LOCK_NAME, LOCK_WAIT) as held:\n            if not held:\n                return False",
     "        with file_lock(LOCK_NAME + '.none', LOCK_WAIT) as held:\n            if not held:\n                return False",
     "tests/test_gatecall.py::Company::test_no_stop_is_lost_while_hooks_and_passes_write_at_once", "red"),
    ("a stop rewrites the journal inside its hook", GATECALL,
     "        if append_record(record, days, where, counted_kinds):\n            tend_in_background()",
     "        if append_record(record, days, where, counted_kinds):\n            tend_journal(LOCK_WAIT)",
     "tests/test_gatecall.py::Company::test_a_stop_only_adds_its_line_and_the_journal_is_tended_in_a_process_of_its_own",
     "red"),
    ("a line an older gatecall adds after the move is never noticed", GATECALL,
     'foreign = state.get("size") != before', "foreign = False",
     "tests/test_gatecall.py::Company::test_a_line_an_older_gatecall_adds_after_the_move_is_signed_too", "red"),
    ("every record tended by the policy of the folder the journal is read from", GATECALL,
     "self.seen[(cwd, session)] = read_policy(None, cwd, project=cwd is not None, session=session)",
     "self.seen[(cwd, session)] = read_policy(None, None)",
     "tests/test_gatecall.py::Company::test_each_record_is_kept_by_the_policy_of_the_folder_it_was_written_in", "red"),
    ("a folder with a policy of its own tends every record by it", GATECALL,
     "self.seen[(cwd, session)] = read_policy(None, cwd, project=cwd is not None, session=session)",
     "self.seen[(cwd, session)] = read_policy(None, None) if read_policy(None, None)[1] else "
     "read_policy(None, cwd, project=cwd is not None, session=session)",
     "tests/test_gatecall.py::Company::test_each_record_is_kept_by_the_policy_of_the_folder_it_was_written_in", "red"),
    ("every record tended by the $COMPANY_AI_POLICY of the session tending it", GATECALL,
     "    named = record.get(\"company_ai_policy\")\n    return named if isinstance(named, str) else \"\"",
     "    return None",
     "tests/test_gatecall.py::Company::test_a_record_keeps_the_company_ai_policy_of_the_session_that_wrote_it", "red"),
    ("a relative $COMPANY_AI_POLICY kept as written, for another session to read from its own folder", GATECALL,
     'record["company_ai_policy"] = os.path.abspath(named)', 'record["company_ai_policy"] = named',
     "tests/test_gatecall.py::Company::test_a_record_keeps_the_company_ai_policy_of_the_session_that_wrote_it", "red"),
    ("a 0.1.3 record signed without the $COMPANY_AI_POLICY that stood in for its session's", GATECALL,
     "record = with_session(sign_legacy(record, policies.key(policy, where), counted_for(policy)))",
     "record = sign_legacy(record, policies.key(policy, where), counted_for(policy))",
     "tests/test_gatecall.py::Company::test_a_record_keeps_the_company_ai_policy_of_the_session_that_wrote_it", "red"),
    ("the company folder's policy ignored in its subfolders", GATECALL,
     "        current = parent if parent != current else None", "        current = None",
     "tests/test_gatecall.py::Company::test_a_policy_in_the_company_folder_holds_in_every_folder_inside_it", "red"),
    ("a relative key file read from wherever the hook runs", GATECALL,
     "return place(named, os.path.dirname(where) if where else None)", "return place(named, None)",
     "tests/test_gatecall.py::Company::test_a_relative_key_file_is_read_from_the_policy_files_folder", "red"),
    ("the model reads gatecall's journal and key", GATECALL,
     "    own = own_hit(tool, data, text, cwd, policy, where)", "    own = None",
     "tests/test_gatecall.py::Company::test_the_model_never_reads_gatecalls_journal_or_key", "red"),
    ("~/.gatecall named in a command passes", GATECALL,
     "        if OWN_NAME.search(words) or any(", "        if False and any(",
     "tests/test_gatecall.py::Company::test_the_model_never_reads_gatecalls_journal_or_key", "red"),
    ("the permissions block leaves the journal's key open", GATECALL,
     '    deny.append("Read(%s)" % key)', "    pass",
     "tests/test_gatecall.py::Company::test_settings_close_red_folders_by_absolute_path", "red"),
    ("a key the person owns left readable by others", GATECALL,
     "            os.chmod(path, 0o600)\n            return None", "            return None",
     "tests/test_gatecall.py::Company::test_a_key_the_person_owns_is_kept_theirs_alone_and_another_users_is_named",
     "red"),
    ("no access list on Windows", GATECALL,
     "        who = windows_user()\n        if who:", "        who = None\n        if who:",
     "tests/test_gatecall.py::Company::"
     "test_on_windows_every_file_gatecall_makes_has_its_owner_alone_on_its_access_list", "red"),
    ("the key written in a folder others can open, its access list set only after", GATECALL,
     "        owner_only(private, folder=True)\n", "",
     "tests/test_gatecall.py::Company::"
     "test_on_windows_every_file_gatecall_makes_has_its_owner_alone_on_its_access_list", "red"),
    ("the journal opened without O_BINARY", GATECALL,
     "os.O_WRONLY | os.O_APPEND | os.O_CREAT | BINARY", "os.O_WRONLY | os.O_APPEND | os.O_CREAT",
     "tests/test_gatecall.py::Company::test_every_file_gatecall_opens_by_descriptor_is_opened_in_binary_mode", "red"),
    ("the key written in place, where a hook reads half of it", GATECALL,
     "                os.replace(tmp, path)", "                open(path, 'w').close()",
     "tests/test_gatecall.py::Company::test_hooks_making_the_key_at_once_end_with_one_whole_key", "red"),
    ("a list fingerprinted by its length", DETECT,
     'count=len(addresses), key=key, mark="\\n".join(sorted(addresses))))', "count=len(addresses), key=key))",
     "tests/test_detect.py::Fingerprints", "red"),
    ("an ID number fingerprinted as it was typed", DETECT,
     "mark=id_mark(m.group(0))))", "mark=m.group(0)))",
     "tests/test_detect.py::Fingerprints", "red"),
    ("a stop counted twice when its kind is its rule", GATECALL,
     'set(strings(record.get("kinds"))) | set(strings(record.get("rules")))',
     'strings(record.get("kinds")) + strings(record.get("rules"))',
     "tests/test_gatecall.py::Company::test_the_journal_keeps_a_fingerprint_under_the_companys_own_key", "red"),
    ("an exported cell runs as a spreadsheet formula", GATECALL,
     """return "'" + value if value[:1] in ("=", "+", "-", "@", "\\t", "\\r") else value""", "return value",
     "tests/test_gatecall.py::Company::test_the_export_gives_the_kept_records_as_json_lines_or_csv", "red"),
    ("a kind moved to a count keeps the fingerprints it had before", GATECALL,
     "kept = keep_count_only(record, counted_for(policy))", "kept = None",
     "tests/test_gatecall.py::Company::test_a_kind_moved_to_a_count_loses_the_fingerprints_it_had_before", "red"),
    ("a kind moved to a count is shown and exported with its fingerprints", GATECALL,
     "record = keep_count_only(record, counted_for(policy)) or record", "record = record",
     "tests/test_gatecall.py::Company::test_a_kind_moved_to_a_count_loses_the_fingerprints_it_had_before", "red"),
    ("a stop under a new count-only rule starts no pass", GATECALL,
     'recount = bool(set(counted_kinds) - set(strings(known.get(where or ""))))', "recount = False",
     "tests/test_gatecall.py::Company::test_a_kind_moved_to_a_count_loses_the_fingerprints_it_had_before", "red"),
    ("scan makes a key when there is none", GATECALL,
     "key = journal_key(policy, where, make=False) if args.json else None",
     "key = journal_key(policy, where, make=True) if args.json else None",
     "tests/test_gatecall.py::Company::test_scan_names_the_key_of_each_fingerprint_and_never_makes_one", "red"),
    ("scan --json without the id of the key", GATECALL,
     'item["key_id"] = key.name()', 'item["key_id"] = None',
     "tests/test_gatecall.py::Company::test_scan_names_the_key_of_each_fingerprint_and_never_makes_one", "red"),
    ("the key left in the output of a step that reached it", GATECALL,
     "found = [key for key in known_keys(policy, where) if any(key.lower() in text for text in leaves)]",
     "found = []",
     "tests/test_gatecall.py::Company::test_the_key_is_taken_out_of_whatever_output_a_step_reached_it_in", "red"),
    ("a PowerShell command reads the key", GATECALL,
     'if tool in ("Bash", "PowerShell") or tool.startswith("mcp__"):', 'if tool == "Bash" or tool.startswith("mcp__"):',
     "tests/test_gatecall.py::Company::test_the_model_never_reads_gatecalls_journal_or_key", "red"),
    ("the permissions block leaves gatecall's folder open to edits", GATECALL,
     '    deny.append("Edit(%s/**)" % rule_path(os.path.abspath(gatecall_home())).rstrip("/"))', "    pass",
     "tests/test_gatecall.py::Company::test_settings_close_red_folders_by_absolute_path", "red"),
    ("a key inside a git work tree goes in with `git add -A`", GATECALL,
     "            guard_key(path)\n            keep_out_of_git(path)", "            guard_key(path)",
     "tests/test_gatecall.py::Company::test_a_key_inside_a_git_work_tree_is_never_committed", "red"),
    ("a journal that cannot be read is shown as an empty one", GATECALL,
     'raise Problem("cannot read the journal %s: %s" % (name, exc.strerror or exc))', "continue",
     "tests/test_gatecall.py::Company::test_a_journal_that_cannot_be_read_is_said_so_never_shown_empty", "red"),
    ("the version differs between the manifest and the catalogue", PLUGIN_JSON,
     '"version": "0.1.4"', '"version": "0.1.5"',
     "tests/test_gatecall.py::Release", "red"),
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
