#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gatecall: what may leave the company, and where it may go. It stops; it never sends anything.

  gatecall.py hook start|prompt|tool|output
      The four hooks (hooks/hooks.json), the hook's JSON on stdin. start: one line naming the profile and
      the red folders. prompt: a message holding a key, a card, an IBAN, an ID number or a list of people
      is stopped before it leaves. tool: the same for commands, web requests and tool calls; red folders
      are read only by a model on this computer; kimi, grok and agy are kept to their rules; gatecall's own
      journal and key are opened by gatecall alone. output: the company's journal key, wherever a step found
      it, is taken out of the step's output before the model reads it.
  gatecall.py scan [FILE] [--profile P ...] [--country CC] [--policy FILE] [--json]
      What in a file (or stdin) would be stopped, masked. Exit 1 when something would. --json: each value with the
      fingerprint the journal would hold and its key's key_id, or why it has none; the key is read, never made.
  gatecall.py settings [--policy FILE] [--out FILE]
      The permissions.deny block for Claude Code: Read and Edit of every red folder by its absolute
      //path, and WebFetch of the hosts the profile denies.
  gatecall.py route [--color red|yellow|green] [--policy FILE]
      Where each colour of data may go, from the company's policy and profiles.
  gatecall.py copy SOURCE DEST [--policy FILE]
      A cleaned copy for an agent that works only on copies: no red folder, no key file, no .git.
  gatecall.py mark --training FOLDER
      A person marks a folder of practice files as a training folder.
  gatecall.py journal [--days N] [--export FILE] [--format jsonl|csv] [--policy FILE]
      What was stopped, by kind and rule, and how often the same value came back - never the values themselves:
      each value is a fingerprint under the company's own key (HMAC-SHA256), or only a count. --export writes every
      kept record (or those of the last N days) for the company's security team ("-": to the screen).
  gatecall.py tend
      The journal kept to the rules of the folder each record was written in (and of the $COMPANY_AI_POLICY of the
      session that wrote it): records past their retention period deleted, a 0.1.3 journal's fingerprints signed
      again. The hooks start it in the background.
  gatecall.py profiles
      The profiles and the program rules, with their reasons.

Standard library only, no network. Exit 0: fine. 1: something would be stopped. 2: bad input.
A hook never fails the session: an internal error is written to the journal and the step goes on.
"""
import argparse
import contextlib
import csv
import datetime
import fnmatch
import io
import json
import os
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile

try:
    import fcntl                        # macOS, Linux: the journal's lock is the kernel's flock
except ImportError:
    fcntl = None
try:
    import msvcrt                       # Windows: the journal's lock is a byte the kernel locks
except ImportError:
    msvcrt = None

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import detect  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
PROFILES = os.path.join(ROOT, "data", "profiles.json")
LANG_DIR = os.path.join(ROOT, "lang")
POLICY_NAME = "company-ai-policy.json"
MANAGED_DIRS = {
    "darwin": "/Library/Application Support/ClaudeCode",
    "linux": "/etc/claude-code",
    "win32": "C:\\Program Files\\ClaudeCode",
}
TRAINING_MARK = ".gatecall-training"
COPY_MARK = ".gatecall-copy"
LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0")
MODEL_ENV = ("ANTHROPIC_MODEL", "ANTHROPIC_DEFAULT_OPUS_MODEL", "ANTHROPIC_DEFAULT_SONNET_MODEL",
             "ANTHROPIC_DEFAULT_HAIKU_MODEL", "ANTHROPIC_SMALL_FAST_MODEL")
# Files a copy for another agent never carries: keys, certificates, password stores, package tokens.
SECRET_FILES = (".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa", "id_dsa", "id_ecdsa",
                "id_ed25519", ".npmrc", ".pypirc", ".netrc", "credentials", "credentials.json", "*.kdbx",
                TRAINING_MARK, COPY_MARK)
SKIP_IN_COPY = (".git", "__pycache__", "node_modules", ".venv")
# The red window (routecall's local-red profile) carries this mark; only that session opens the red folders.
WINDOW_VAR = "ROUTECALL_WINDOW"
RED_WINDOW = "local-red"
# Programs that reach other machines: in the red window they may talk to this computer only.
NET_PROGRAMS = ("curl", "wget", "ssh", "scp", "sftp", "rsync", "nc", "ncat", "netcat", "telnet", "ftp", "aria2c",
                "http", "https", "xh")
# A cleaned copy reads each file: text is masked, office documents part by part; what cannot be read as text
# (a PDF, an image, any file with NUL bytes) stays out of the copy and is named with the reason.
TEXT_SNIFF = 8192
OFFICE_ZIP = (".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp")
NOT_TEXT = (".pdf",)
FILE_TOOLS = ("Read", "Edit", "Write", "MultiEdit", "NotebookEdit")
SEARCH_TOOLS = ("Grep", "Glob")
OUTGOING_TOOLS = ("WebFetch", "WebSearch")
PATH_FLAGS = ("--cwd", "--dir", "--work-dir", "--workdir", "-C", "-w")
BLANKET = re.compile(r'command\(\s*\*\s*\)|"\s*\*\s*"|\(\.\*\)|"\.\*"')
SHELL_SPLIT = re.compile(r"\|\||&&|[;|\n]")
# The journal: a line per stop. Its fingerprints are HMAC-SHA256 under the company's own key, made at its first use
# beside the journal and readable by its owner only; a record is deleted when the retention period of the folder it
# was written in is over.
JOURNAL_NAME = "journal.jsonl"
KEY_NAME = "journal.key"
STATE_NAME = "journal.state"
PENDING_NAME = "journal.pending"
LOCK_NAME = "journal.lock"
TEND_LOCK_NAME = "tend.lock"
KEY_LOCK_NAME = "key.lock"
KEY_MIN = 32                        # characters: a key file shorter than this keeps no secret and is not used
KEY_LABEL = "gatecall journal key"
RETENTION_DAYS = 90
STAMP = "%Y-%m-%dT%H:%M:%SZ"
# A 0.1.0-0.1.3 fingerprint (sha256 without a key) is signed again under the key with this in front, so it never
# equals a fingerprint made since.
LEGACY = "gatecall 0.1.3 sha256[:12] "
LOCK_WAIT = 2.0                     # seconds a hook waits for the journal's lock; then its line goes to journal.pending/
TEND_WAIT = 10.0                    # seconds the journal command waits for a pass already running
BINARY = getattr(os, "O_BINARY", 0)     # Windows: a descriptor opened without it turns every \n into \r\n
WINDOWS = os.name == "nt"
EXPORT_FIELDS = ("time", "event", "tool", "cwd", "kinds", "rules", "counted", "key_id", "fingerprints",
                 "legacy_fingerprints", "key_problem", "keep_until", "company_ai_policy")
# gatecall's own files, named in a command or a tool's input: ~/.gatecall, $GATECALL_HOME, $GATECALL_KEY_FILE.
OWN_NAME = re.compile(r"(?<![\w-])\.gatecall(?![\w.-])")
OWN_VARS = ("GATECALL_HOME", "GATECALL_KEY_FILE")
# What stands in a step's output where the company's journal key was (hook output).
OUTPUT_MARK = "[the company's journal key - gatecall keeps it out]"


class Problem(Exception):
    """Input gatecall cannot use. Printed as one line; exit 2."""


# ---------------------------------------------------------------- files and words -------------

def load_json(path, what):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError) as exc:
        raise Problem("cannot read %s %s: %s" % (what, path, exc))


def lang_words(code):
    """lang/<code>.json over lang/en.json: the person's language, English underneath."""
    words = {}
    for name in ("en", code):
        path = os.path.join(LANG_DIR, "%s.json" % name)
        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, dict) and isinstance(words.get(key), dict):
                    merged = dict(words[key])
                    merged.update(value)
                    words[key] = merged
                else:
                    words[key] = value
    return words


def pick_lang(policy=None, env=None):
    env = os.environ if env is None else env
    for value in ((policy or {}).get("language"), env.get("GATECALL_LANG"), env.get("LC_ALL"),
                  env.get("LC_MESSAGES"), env.get("LANG")):
        if isinstance(value, str) and len(value) >= 2:
            code = value[:2].lower()
            if os.path.exists(os.path.join(LANG_DIR, "%s.json" % code)):
                return code
    return "en"


def say(words, key, **values):
    text = words.get(key) or key
    try:
        return text.format(**values)
    except (KeyError, IndexError, ValueError):
        return text


# ---------------------------------------------------------------- the company policy file -----

def policy_paths(cwd=None, project=True, session=None):
    """Where company-ai-policy.json is looked for, the binding one first: the managed copy an
    administrator installed, then $COMPANY_AI_POLICY (`session`: the one another session had - "" for none - in place
    of this process's), then the project folder and each folder above it (a policy in the company folder holds in
    every folder inside it), then the person's own."""
    out = []
    managed = MANAGED_DIRS.get(sys.platform)
    if managed:
        out.append(os.path.join(managed, POLICY_NAME))
    env = os.environ.get("COMPANY_AI_POLICY") if session is None else session
    if env:
        out.append(env)
    current = os.path.abspath(cwd or os.getcwd()) if project else None
    while current:
        out.append(os.path.join(current, POLICY_NAME))
        out.append(os.path.join(current, ".claude", POLICY_NAME))
        parent = os.path.dirname(current)
        current = parent if parent != current else None
    out.append(os.path.join(os.path.expanduser("~"), ".claude", POLICY_NAME))
    return out


def read_policy(explicit=None, cwd=None, project=True, session=None):
    """-> (policy dict, path) or ({}, None). A file that does not parse is a Problem, not silence. Without `project`,
    only the policies that bind in every folder: the managed one, $COMPANY_AI_POLICY, the person's own."""
    for path in ([explicit] if explicit else policy_paths(cwd, project, session)):
        if path and os.path.isfile(path):
            data = load_json(path, "the company policy")
            if not isinstance(data, dict):
                raise Problem("%s must hold one JSON object" % path)
            return data, path
    if explicit:
        raise Problem("no company policy at %s" % explicit)
    return {}, None


def policy_list(policy, key):
    value = (policy or {}).get(key) or []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        raise Problem("%s in the company policy must be a list" % key)
    return [v for v in value if isinstance(v, str) and v.strip()]


def folders(policy, key, real=True):
    """The folders a policy names under `key`, ~ and $VARS expanded, absolute (real paths for matching)."""
    out = []
    for item in policy_list(policy, key):
        path = os.path.abspath(os.path.expandvars(os.path.expanduser(item.strip())))
        out.append(os.path.realpath(path) if real else path)
    return out


def under(path, places):
    """The place among `places` that holds `path` (itself or anything inside it), or None."""
    real = os.path.realpath(path)
    for place in places:
        if real == place or real.startswith(place.rstrip(os.sep) + os.sep):
            return place
    return None


# ---------------------------------------------------------------- profiles ----------------------

def load_profiles(path=None):
    doc = load_json(path or PROFILES, "gatecall's profiles")
    if not isinstance(doc, dict) or not isinstance(doc.get("profiles"), dict):
        raise Problem("the profiles file has no profiles")
    return doc


def one_profile(doc, name):
    """A profile with everything it extends folded in: the child's numbers win, lists join."""
    chain = []
    seen = set()
    current = name
    while current:
        if current in seen:
            raise Problem("profile %s extends itself" % current)
        seen.add(current)
        profile = doc["profiles"].get(current)
        if not isinstance(profile, dict):
            raise Problem("no profile %r (gatecall knows: %s)" % (current, ", ".join(sorted(doc["profiles"]))))
        chain.append(profile)
        current = profile.get("extends")
    out = {"block": set(), "deny_models": set(), "deny_hosts": set()}
    for profile in reversed(chain):
        for key in ("block", "deny_models", "deny_hosts"):
            out[key] |= set(profile.get(key) or [])
        for key in ("email_batch", "phone_batch", "national_ids"):
            if key in profile:
                out[key] = profile[key]
    return out


def resolve(doc, names):
    rules = {"names": list(names), "block": set(), "deny_models": set(), "deny_hosts": set(),
             "email_batch": None, "phone_batch": None, "modes": set()}
    for name in names:
        one = one_profile(doc, name)
        for key in ("block", "deny_models", "deny_hosts"):
            rules[key] |= one[key]
        for key in ("email_batch", "phone_batch"):
            value = one.get(key)
            if isinstance(value, int) and value > 0:
                rules[key] = value if rules[key] is None else min(rules[key], value)
        if one.get("national_ids"):
            rules["modes"].add(one["national_ids"])
    return rules


def id_kinds(doc, modes, country):
    out = set(doc.get("distinctive_ids") or [])
    for mode in modes:
        if mode == "all":
            out |= set(doc.get("national_ids") or {})
        elif mode == "eu":
            out |= set(doc.get("eu_ids") or [])
        elif mode == "country" and isinstance(country, str) and country.strip():
            out |= set(k for k, v in (doc.get("national_ids") or {}).items()
                       if v.get("country") == country.strip().upper())
    return sorted(k for k in out if k in detect.NATIONAL_IDS)


def catalogue(doc):
    """The national ID catalogue with every language's own context words added (lang/*.json, id_context):
    the Russian or Ukrainian word for a taxpayer number lives with its language, not in this file."""
    out = {}
    for key, info in (doc.get("national_ids") or {}).items():
        out[key] = dict(info, context=list(info.get("context") or []))
    for name in sorted(os.listdir(LANG_DIR)) if os.path.isdir(LANG_DIR) else []:
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(LANG_DIR, name), encoding="utf-8") as handle:
                extra = json.load(handle).get("id_context") or {}
        except (OSError, ValueError, AttributeError):
            continue
        for key, words in extra.items():
            if key in out and isinstance(words, list):
                out[key]["context"].extend(w for w in words if isinstance(w, str) and w)
    return out


def host_entry(hosts, host):
    """The most specific entry of the hosts table for a host, or None."""
    best = None
    for domain, entry in hosts.items():
        if host_matches(host, domain) and (best is None or len(domain) > len(best[0])):
            best = (domain, entry)
    return best


def policy_denies(doc, policy):
    """The company policy's own denials on top of its profiles: deny_hosts and deny_models as written,
    deny_jurisdictions (every API host of the hosts table processing data there - a host whose more specific
    domain lies elsewhere stays allowed) and deny_providers (the vendor's hosts and model names).
    -> (hosts, models, allowed): allowed are the more specific domains kept open inside a denied one."""
    hosts = doc.get("hosts") or {}
    deny_hosts = set(h.strip().lower() for h in policy_list(policy, "deny_hosts") if h.strip())
    deny_models = set(m.strip().lower() for m in policy_list(policy, "deny_models") if m.strip())
    places = set(j.strip().upper() for j in policy_list(policy, "deny_jurisdictions") if j.strip())
    vendors = [v.strip().lower() for v in policy_list(policy, "deny_providers") if v.strip()]
    keep = set()
    for domain, entry in sorted(hosts.items()):
        vendor = str(entry.get("vendor", "")).lower()
        by_vendor = any(name in vendor for name in vendors)
        if by_vendor:
            deny_hosts.add(domain)
            deny_models |= set(entry.get("models") or [])
        elif str(entry.get("jurisdiction", "")).upper() in places:
            deny_hosts.add(domain)
    for domain, entry in sorted(hosts.items()):
        vendor = str(entry.get("vendor", "")).lower()
        if domain in deny_hosts or any(name in vendor for name in vendors):
            continue
        if any(host_matches(domain, denied) for denied in deny_hosts):
            keep.add(domain)
    return deny_hosts, deny_models, keep


def context(policy=None, names=None, country=None):
    """Everything a check needs: the rules of the company's profiles, the ID kinds, the catalogue."""
    doc = load_profiles()
    names = list(names or policy_list(policy, "profiles") or ["default"])
    rules = resolve(doc, names)
    extra_hosts, extra_models, keep = policy_denies(doc, policy)
    if extra_hosts - rules["deny_hosts"] or extra_models - rules["deny_models"]:
        rules["names"] = rules["names"] + ["company policy"]
    rules["deny_hosts"] |= extra_hosts
    rules["deny_models"] |= extra_models
    rules["keep_hosts"] = keep
    rules["ids"] = id_kinds(doc, rules["modes"], country or (policy or {}).get("country"))
    rules["catalogue"] = catalogue(doc)
    rules["programs"] = doc.get("programs") or {}
    rules["email_batch"] = rules["email_batch"] or 5
    rules["phone_batch"] = rules["phone_batch"] or 5
    return rules


def findings_in(text, rules, key=None):
    return [f for f in detect.scan(text, rules["ids"], rules["catalogue"], rules["email_batch"],
                                   rules["phone_batch"], key) if f["kind"] in rules["block"]]


# ---------------------------------------------------------------- where this session runs ------

def session_route(env=None):
    """The model provider of this session, from the environment Claude Code passes to its hooks."""
    env = os.environ if env is None else env
    base = env.get("ANTHROPIC_BASE_URL") or ""
    match = re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://(\[[^\]]+\]|[^/:?#]+)", base.strip())
    host = match.group(1).lower() if match else ""
    models = [env.get(k) for k in MODEL_ENV if env.get(k)]
    return {"base": base, "host": host, "local": host in LOCAL_HOSTS, "models": models}


def cloud_model(name):
    """Ollama's cloud models answer on localhost too, and their names end in -cloud or :cloud."""
    low = str(name or "").strip().lower()
    return low.endswith("-cloud") or low.endswith(":cloud")


def red_window(route, env):
    """The one session that opens the red folders: a model on this computer, the mark of routecall's local-red
    profile, and no cloud model behind the local address. An ordinary local window is not it."""
    return bool(route["local"] and str(env.get(WINDOW_VAR) or "") == RED_WINDOW
                and not any(cloud_model(m) for m in route["models"]))


def outside_hosts(command, cwd):
    """What a network program in a command would reach beyond this computer: the outside hosts it names, or
    'PROGRAM ?' when it names no address at all (ssh host, scp file host:)."""
    out = []
    for name, argv, _folder in command_calls(command, cwd):
        if name not in NET_PROGRAMS:
            continue
        hosts = re.findall(r"[a-z][a-z0-9+.-]*://(\[[^\]]+\]|[^/:?#\s\"'@]+)", " ".join(argv[1:]).lower())
        if not hosts:
            out.append("%s ?" % name)
        out.extend(h for h in hosts if h not in LOCAL_HOSTS)
    return out


def host_matches(host, domain):
    return host == domain or host.endswith("." + domain)


def host_denied(host, rules):
    """A host the rules deny, unless a more specific domain the company keeps open holds it."""
    if any(host_matches(host, keep) for keep in rules.get("keep_hosts") or ()):
        return False
    return any(host_matches(host, d) for d in rules["deny_hosts"])


def denied_route(route, rules, words):
    out = []
    profile = ", ".join(rules["names"])
    if route["host"] and host_denied(route["host"], rules):
        out.append(("route", say(words, "denied_route", what=route["host"], profile=profile)))
    for model in route["models"]:
        if any(word in model.lower() for word in rules["deny_models"]):
            out.append(("route", say(words, "denied_route", what=model, profile=profile)))
    return out


MODEL_FLAGS = ("--model", "-m", "--model-id", "run", "pull", "download", "serve", "load")


def model_words(tool, data, text):
    """The words that name a model to run: after --model, -m, `ollama run`/`pull`, as NAME=model or a
    hub id owner/model in a command; any value under a key named *model* in a tool's input. Talking about
    a model (a price table, a news page) is not running it."""
    out = []
    if tool == "Bash":
        for segment in SHELL_SPLIT.split(text or ""):
            words = split_words(segment.strip())
            for i, word in enumerate(words):
                low = word.lower()
                if (i > 0 and words[i - 1] in MODEL_FLAGS) or low.startswith("--model=") \
                        or re.match(r"^[a-z_][a-z0-9_]*=", low) \
                        or (i > 0 and re.match(r"^[a-z0-9][a-z0-9_.-]*/[a-z0-9][a-z0-9_.:-]*$", low)):
                    out.append(low)
        return out

    def walk(value, key=""):
        if isinstance(value, dict):
            for k, v in value.items():
                walk(v, str(k))
        elif isinstance(value, list):
            for v in value:
                walk(v, key)
        elif isinstance(value, str) and "model" in key.lower():
            out.append(value.lower())
    walk(data)
    return out


def url_hosts(tool, data, text):
    """The hosts a step talks to: the URL of a web request, every http(s) address in a command or an input."""
    found = re.findall(r"[a-z][a-z0-9+.-]*://(\[[^\]]+\]|[^/:?#\s\"'@]+)", (text or "").lower())
    if tool == "Bash":
        for word in re.findall(r"(?<![\w.@/-])((?:[a-z0-9-]+\.)+[a-z]{2,})(?![\w-])", (text or "").lower()):
            found.append(word)
    return found


def denied_targets(tool, data, text, rules, words):
    """Hosts and models the profile denies, used by a command, a web request or a tool's input."""
    out = []
    profile = ", ".join(rules["names"])
    hosts = url_hosts(tool, data, text)
    for domain in sorted(rules["deny_hosts"]):
        if any(host_matches(host, domain) and host_denied(host, rules) for host in hosts):
            out.append(("denied-host", say(words, "denied_target", what=domain, profile=profile)))
    named = model_words(tool, data, text)
    for model in sorted(rules["deny_models"]):
        if any(model in word for word in named):
            out.append(("denied-model", say(words, "denied_target", what=model, profile=profile)))
    return out


# ---------------------------------------------------------------- commands ----------------------

def split_words(segment):
    try:
        return shlex.split(segment, posix=True)
    except ValueError:
        return segment.split()


def resolve_path(word, cwd):
    return os.path.abspath(os.path.join(cwd, os.path.expandvars(os.path.expanduser(word))))


def command_calls(command, cwd):
    """(program name, words, folder) of every program a shell command starts, `cd` followed."""
    calls = []
    folder = cwd
    for segment in SHELL_SPLIT.split(command or ""):
        words = split_words(segment.strip())
        while words and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[0])
                         or words[0] in ("sudo", "exec", "command", "env", "nohup", "time")):
            words = words[1:]
        if not words:
            continue
        if words[0] == "cd" and len(words) > 1:
            folder = resolve_path(words[1], folder)
            continue
        where = folder
        for i, word in enumerate(words[:-1]):
            if word in PATH_FLAGS:
                where = resolve_path(words[i + 1], folder)
        for word in words[1:]:
            for flag in PATH_FLAGS:
                if word.startswith(flag + "="):
                    where = resolve_path(word[len(flag) + 1:], folder)
        calls.append((os.path.basename(words[0]), words, where))
    return calls


def has_mark(folder, mark):
    current = os.path.realpath(folder)
    while True:
        if os.path.isfile(os.path.join(current, mark)):
            return True
        parent = os.path.dirname(current)
        if parent == current:
            return False
        current = parent


def program_problems(command, cwd, policy, rules, words):
    out = []
    marks_count = (policy or {}).get("markers", True) is not False
    for name, argv, folder in command_calls(command, cwd):
        script = [i for i, word in enumerate(argv) if os.path.basename(word) == "gatecall.py"]
        if script:
            if "mark" in argv[script[0] + 1:]:
                out.append(("mark-by-person", say(words, "mark_by_person")))
            continue
        rule = (rules["programs"].get(name) or {}).get("rule")
        if rule == "training-only":
            ok = (marks_count and has_mark(folder, TRAINING_MARK)) or under(folder, folders(policy, "training_folders"))
            if not ok:
                out.append(("kimi-training-only", say(words, "kimi", folder=folder)))
        elif rule == "copies-only":
            ok = (marks_count and has_mark(folder, COPY_MARK)) or under(folder, folders(policy, "copy_folders"))
            if not ok:
                out.append(("grok-copies-only", say(words, "grok", folder=folder)))
        elif rule == "no-blanket-allow":
            loose = [w for w in argv[1:] if w in ("--yolo", "-y") or w.startswith("--dangerously")
                     or w in ("--approval-mode=yolo",)]
            if "--approval-mode" in argv and argv.index("--approval-mode") + 1 < len(argv) \
                    and argv[argv.index("--approval-mode") + 1] == "yolo":
                loose.append("--approval-mode yolo")
            if loose:
                out.append(("agy-no-blanket-allow", say(words, "agy")))
    if "antigravity" in command and "settings.json" in command and BLANKET.search(command):
        out.append(("agy-no-blanket-allow", say(words, "agy")))
    if TRAINING_MARK in command or COPY_MARK in command:
        out.append(("mark-by-person", say(words, "mark_by_person")))
    return out


def command_paths(command, cwd):
    """Every word of a command that names a place on disk, made absolute (cd followed)."""
    out = []
    folder = cwd
    for segment in SHELL_SPLIT.split(command or ""):
        words = split_words(segment.strip())
        if words and words[0] == "cd" and len(words) > 1:
            folder = resolve_path(words[1], folder)
            out.append(folder)
            continue
        for word in words:
            if "/" in word or word.startswith("~") or word.startswith("."):
                out.append(resolve_path(word, folder))
    return out


# ---------------------------------------------------------------- the journal -------------------

def gatecall_home():
    return os.environ.get("GATECALL_HOME") or os.path.join(os.path.expanduser("~"), ".gatecall")


def home_file(name):
    return os.path.join(gatecall_home(), name)


def journal_path():
    return home_file(JOURNAL_NAME)


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def parse_stamp(value):
    try:
        return datetime.datetime.strptime(value, STAMP).replace(tzinfo=datetime.timezone.utc)
    except (TypeError, ValueError):
        return None


_WHO = []


def windows_user():
    """This person as icacls names them: their SID from whoami, else DOMAIN\\name from the environment."""
    if not _WHO:
        who = None
        try:
            done = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], stdin=subprocess.DEVNULL,
                                  capture_output=True, text=True, timeout=10)
            row = next(csv.reader(io.StringIO(done.stdout.strip())), [])
            if len(row) >= 2 and row[1].strip().startswith("S-1-"):
                who = "*" + row[1].strip()
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
        if not who:
            name = (os.environ.get("USERNAME") or "").strip()
            domain = (os.environ.get("USERDOMAIN") or "").strip()
            who = ("%s\\%s" % (domain, name) if domain and name else name) or None
        _WHO.append(who)
    return _WHO[0]


def owner_only(path, folder=False):
    """A file (or a folder) gatecall made, readable by its owner only: mode 0600 (0700 for a folder); on Windows,
    where a mode does not limit reading, an access list holding this person alone, nothing inherited (icacls, the way
    OpenSSH for Windows keeps a private key). Never raises."""
    try:
        if not WINDOWS:
            os.chmod(path, 0o700 if folder else 0o600)
            return
        who = windows_user()
        if who:
            subprocess.run(["icacls", path, "/inheritance:r", "/grant:r",
                            "%s:%sF" % (who, "(OI)(CI)" if folder else ""), "/q"],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    except (OSError, ValueError, subprocess.SubprocessError):
        pass


def make_home():
    """gatecall's folder, readable by its owner only from the moment it is made."""
    home = gatecall_home()
    if not os.path.isdir(home):
        os.makedirs(home, mode=0o700, exist_ok=True)
        owner_only(home, folder=True)
    return home


def try_lock(fd):
    """One try at the kernel's lock on an open file, without waiting: flock on macOS and Linux, the first byte locked
    on Windows. The kernel lets go of it when its holder exits or is killed. -> whether it is held now."""
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        elif msvcrt is not None:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        return True
    except OSError:
        return False


def unlock(fd):
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_UN)
        elif msvcrt is not None:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    except OSError:
        pass


@contextlib.contextmanager
def file_lock(name, wait):
    """gatecall's lock `name` in its folder, waited for at most `wait` seconds; yields whether it is held. The lock
    file stays in place: the lock itself is the kernel's, so the lock of a hook that was killed is gone with it."""
    make_home()
    fd = os.open(home_file(name), os.O_RDWR | os.O_CREAT | BINARY, 0o600)
    held = False
    try:
        deadline = time.monotonic() + wait
        while True:
            held = try_lock(fd)
            if held or time.monotonic() >= deadline:
                break
            time.sleep(0.01)
        yield held
    finally:
        if held:
            unlock(fd)
        os.close(fd)


def place(named, base):
    """A path a person wrote, ~ and $VARS expanded; a relative one is read from `base` when there is one."""
    path = os.path.expandvars(os.path.expanduser(named.strip()))
    if base and not os.path.isabs(path):
        path = os.path.join(base, path)
    return os.path.abspath(path)


def key_path(policy=None, where=None):
    """Where the company's journal key lives: the policy's journal_key_file - a relative path is read from the folder
    of the policy file (`where`), so every folder under one policy has one key - then $GATECALL_KEY_FILE (a relative
    path from gatecall's own folder), then journal.key beside the journal."""
    named = (policy or {}).get("journal_key_file")
    if isinstance(named, str) and named.strip():
        return place(named, os.path.dirname(where) if where else None)
    named = os.environ.get("GATECALL_KEY_FILE")
    if isinstance(named, str) and named.strip():
        return place(named, gatecall_home())
    return home_file(KEY_NAME)


def make_key(path):
    """64 hex characters - 32 random bytes from `secrets` - into a file only its owner reads, from its first byte. A new
    file takes its folder's access list on Windows, where a mode limits nothing, so the key is written in a folder of
    its own beside the key file - made readable by its owner alone (mkdtemp, then icacls) before the key is in it - and
    no other user opens it, not even while it is written. The file appears whole or not at all - linked (or, on a file
    system without links, renamed) into place - and a key already there is never replaced: two hooks making it at once
    end with one key."""
    folder = os.path.dirname(path)
    if not os.path.isdir(folder):
        os.makedirs(folder, mode=0o700, exist_ok=True)
    private = tempfile.mkdtemp(prefix=".journal-key-", dir=folder)
    try:
        owner_only(private, folder=True)
        tmp = os.path.join(private, KEY_NAME)
        handle = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | BINARY, 0o600)
        with os.fdopen(handle, "w", encoding="ascii", newline="") as out:
            out.write(secrets.token_hex(32) + "\n")
            out.flush()
            os.fsync(out.fileno())
        owner_only(tmp)                     # its own list, which stays with it in the folder it goes to
        try:
            os.link(tmp, path)
        except FileExistsError:
            pass                            # another hook made it first: its key is the key
        except OSError:                     # no hard links here: renamed into place, under the key lock, if still absent
            if not os.path.exists(path):
                os.replace(tmp, path)
    finally:
        shutil.rmtree(private, ignore_errors=True)


def load_key(path):
    try:
        with open(path, "rb") as handle:
            return handle.read().strip()
    except FileNotFoundError:
        return None


def guard_key(path):
    """A key file the person owns is kept readable by them alone (0600), whoever wrote it there, the way ssh wants a
    private key; a key another user owns is left as it is. -> what to tell the company when other users of this
    computer can read the key, or None."""
    if WINDOWS:
        return None
    try:
        info = os.stat(path)
        if not info.st_mode & 0o077:
            return None
        if info.st_uid == os.getuid():
            os.chmod(path, 0o600)
            return None
    except OSError:
        return None
    return "the key %s can be read by other users of this computer (mode %03o): install it readable by its user " \
           "only (mode 600)" % (path, stat.S_IMODE(info.st_mode))


def git_folder(path):
    """-> (the work tree that holds `path`, the folder git keeps its own files in) or (None, None). A worktree or a
    submodule has a .git file naming that folder; info/exclude lives in the folder the worktrees share."""
    folder = os.path.dirname(os.path.abspath(path))
    while True:
        dot = os.path.join(folder, ".git")
        if os.path.isdir(dot):
            return folder, dot
        if os.path.isfile(dot):
            with open(dot, encoding="utf-8") as handle:
                line = handle.read().strip()
            if not line.startswith("gitdir:"):
                return None, None
            git = os.path.join(folder, line[len("gitdir:"):].strip())
            common = os.path.join(git, "commondir")
            if os.path.isfile(common):
                with open(common, encoding="utf-8") as handle:
                    git = os.path.join(git, handle.read().strip())
            return folder, os.path.normpath(git)
        parent = os.path.dirname(folder)
        if parent == folder:
            return None, None
        folder = parent


def keep_out_of_git(path):
    """A key file inside a git work tree is listed in that repository's info/exclude - git's place for one clone's own
    files, never committed nor shared - so `git add -A` and a push never carry the company's key. Never raises."""
    try:
        tree, git = git_folder(path)
        if not tree:
            return
        entry = "/" + os.path.relpath(os.path.abspath(path), tree).replace(os.sep, "/")
        entry = re.sub(r"([\\*?\[!#])", r"\\\1", entry)
        exclude = os.path.join(git, "info", "exclude")
        try:
            with open(exclude, encoding="utf-8") as handle:
                lines = handle.read().splitlines()
        except FileNotFoundError:
            lines = []
        if entry in lines:
            return
        os.makedirs(os.path.dirname(exclude), exist_ok=True)
        with open(exclude, "a", encoding="utf-8") as handle:
            handle.write("%s# gatecall: the company's journal key, never committed\n%s\n"
                         % ("\n" if lines and lines[-1].strip() else "", entry))
    except (OSError, ValueError):
        pass


def read_key(path, make=True):
    """-> (the key, None) or (None, why not). The key is the key file's text without its line end, used as it stands as
    the HMAC key: the 64 hex characters gatecall made, or any key of at least 32 characters the company installed
    itself (the same on every laptop, so their journals match). A missing key is made under gatecall's key lock, so
    no hook ever reads half of one - unless `make` is false: scan checks values against a journal, and a key made then
    would match no journal at all."""
    try:
        key = load_key(path)
        if make and (key is None or len(key) < KEY_MIN):
            with file_lock(KEY_LOCK_NAME, LOCK_WAIT):
                key = load_key(path)
                if key is None:
                    make_key(path)
                    key = load_key(path)
        if key is not None:
            guard_key(path)
            keep_out_of_git(path)
    except OSError as exc:
        return None, "cannot use the key %s: %s" % (path, exc.strerror or exc)
    if key is None and not make:
        return None, "no key at %s: gatecall makes it at the first stop it fingerprints on this computer; to check " \
                     "another computer's journal, name that computer's key with journal_key_file or " \
                     "$GATECALL_KEY_FILE" % path
    if key is None:
        return None, "cannot use the key %s: it was not made" % path
    if len(key) < KEY_MIN:
        return None, "the key %s is shorter than %d characters" % (path, KEY_MIN)
    return key, None


class JournalKey:
    """The company's journal key for one run, read (or made, when `make`) when the first fingerprint needs it: a step
    with nothing to stop never touches it."""

    def __init__(self, policy, where=None, make=True):
        self.path = key_path(policy, where)
        self.make = make
        self.key = self.problem = None
        self.tried = False

    def __call__(self):
        if not self.tried:
            self.tried = True
            self.key, self.problem = read_key(self.path, self.make)
        return self.key

    def name(self):
        """The key's id - an HMAC of a fixed text, which tells nothing of the key - written beside the fingerprints
        made with it (key_id), so fingerprints under two keys are never compared."""
        key = self()
        return detect.fingerprint(KEY_LABEL, key)[:8] if key else None


def journal_key(policy, where=None, make=True):
    """This run's key, or None when nothing is fingerprinted: the journal is off, or every kind is kept only as a
    count."""
    if (policy or {}).get("journal") is False or count_only(policy)[0] >= set(detect.KINDS):
        return None
    return JournalKey(policy, where, make)


def retention_days(policy):
    """journal_retention_days in the company policy, a whole number of days from 1; 90 when it names none."""
    value = (policy or {}).get("journal_retention_days")
    if isinstance(value, bool):
        return RETENTION_DAYS
    try:
        days = int(value)
    except (TypeError, ValueError, OverflowError):
        return RETENTION_DAYS
    return min(days, 36500) if days >= 1 else RETENTION_DAYS


def since(days):
    return utcnow() - datetime.timedelta(days=days)


def count_only(policy):
    """The kinds the company keeps in the journal only as a count, with no fingerprint (journal_count_only): a list
    of kinds, or true for all of them. -> (those kinds, the names in the list that are not a kind)."""
    value = (policy or {}).get("journal_count_only")
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return (set(detect.KINDS) if value else set()), []
    return (set(v for v in value if v in detect.KINDS),
            sorted(set(str(v) for v in value if v not in detect.KINDS)))


def counted_for(policy):
    """The kinds a folder's policy keeps only as a count; with its journal off, every kind."""
    return set(detect.KINDS) if (policy or {}).get("journal") is False else count_only(policy)[0]


def strings(value):
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def parse_record(line):
    """-> (a journal record, its time) or (None, None) for a line that is not one."""
    try:
        record = json.loads(line)
        when = datetime.datetime.strptime(record["time"], STAMP).replace(tzinfo=datetime.timezone.utc)
    except (ValueError, KeyError, TypeError):
        return None, None
    return record, when


def session_policy(record):
    """The $COMPANY_AI_POLICY of the session that wrote a record: the one it names, "" when it names none; None for a
    record from before 0.1.4, which never said - the variable of the session tending it stands in."""
    if "key_id" not in record:
        return None
    named = record.get("company_ai_policy")
    return named if isinstance(named, str) else ""


def with_session(record):
    """A record takes this session's $COMPANY_AI_POLICY along, when it has one - as an absolute path, the way this
    session read it - so every other session keeps the record by it too. -> the record."""
    named = os.environ.get("COMPANY_AI_POLICY")
    if named:
        record["company_ai_policy"] = os.path.abspath(named)
    return record


class Policies:
    """The company policy of each folder the records name, read once per run. The journal is one file per person while
    policies are per folder - and $COMPANY_AI_POLICY per session - so a record is kept, signed and counted by the rules
    of the folder it was written in and of the session that wrote it, as the hook that wrote it was, whichever folder
    and session the journal is tended or read from."""

    def __init__(self):
        self.seen = {}
        self.keys = {}

    def of(self, cwd, session=None):
        """-> (policy, path) of a record's folder; a record with no folder has the policies that bind everywhere."""
        cwd = cwd.strip() if isinstance(cwd, str) and cwd.strip() else None
        if (cwd, session) not in self.seen:
            try:
                self.seen[(cwd, session)] = read_policy(None, cwd, project=cwd is not None, session=session)
            except Problem:                 # a policy that does not parse: the default rules, as its hooks had
                self.seen[(cwd, session)] = ({}, None)
        return self.seen[(cwd, session)]

    def key(self, policy, where):
        path = key_path(policy, where)
        if path not in self.keys:
            self.keys[path] = JournalKey(policy, where)
        return self.keys[path]


def expiry(record, when, policy, where):
    """When a record falls due: its time plus the retention period of its own folder's policy, as that policy stands
    now (a period shortened since holds for the records already kept); a record whose folder no policy covers any more,
    at the keep_until it was written with."""
    if where is None:
        until = parse_stamp(record.get("keep_until"))
        if until is not None:
            return until
    return when + datetime.timedelta(days=retention_days(policy))


def sign_legacy(record, key, counted_kinds=()):
    """A record written before 0.1.4 (it has no key_id): its fingerprints are sha256 without a key, and trying every
    number of an ID's range finds the number again. They are signed again under the key of the record's own folder and
    kept apart as legacy_fingerprints - a value stopped twice before still shows as a repeat, never as a repeat of one
    stopped since - and the unkeyed digests are no longer in the journal. A record holding a kind its folder keeps only
    as a count loses its fingerprints instead (they cannot be told apart by kind), and so does one whose key cannot be
    used, with the reason. -> the new record."""
    old = sorted(set(strings(record.get("fingerprints"))))
    out = dict(record)
    out["fingerprints"] = []
    out["key_id"] = None
    if old and set(strings(record.get("kinds"))) & set(counted_kinds):
        old = []
    if old:
        if key is not None and key():
            out["legacy_fingerprints"] = sorted(set(detect.fingerprint(LEGACY + mark, key) for mark in old))
            out["key_id"] = key.name()
        else:
            out["key_problem"] = key.problem if key is not None else "no key in this folder's policy"
    return out


def keep_count_only(record, counted_kinds):
    """A record of 0.1.4 kept to its folder's count-only kinds as the policy stands now. A kind the company moved to a
    count after the record was written - in the record's kinds, not in its `counted` - had its values fingerprinted:
    the record loses its fingerprints, all of them, since they cannot be told apart by kind (as a 0.1.3 record does in
    sign_legacy). A kind the record already kept as a count needs nothing. -> the new record, or None when the record
    keeps to the policy as it is."""
    counted = record.get("counted") if isinstance(record.get("counted"), dict) else {}
    moved = (set(strings(record.get("kinds"))) & set(counted_kinds)) - set(counted)
    if not moved or not (strings(record.get("fingerprints")) or strings(record.get("legacy_fingerprints"))):
        return None
    out = dict(record, fingerprints=[], key_id=None)
    out.pop("legacy_fingerprints", None)
    return out


def replace_file(path, data, guard=True):
    """A new file beside the old one (readable by its owner only when `guard`), then a rename: a reader sees the old
    file or the new one, never half of it."""
    handle, tmp = tempfile.mkstemp(prefix=".journal-", dir=os.path.dirname(path))
    try:
        with os.fdopen(handle, "wb") as out:
            out.write(data)
        if guard:
            owner_only(tmp)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_state():
    """The journal's state: its size after gatecall's last write, when its next record falls due, the oldest record
    kept under each policy file and the kinds each policy file keeps only as a count - what lets a hook see in one read
    that the journal wants a tend."""
    try:
        with open(home_file(STATE_NAME), encoding="utf-8") as handle:
            state = json.load(handle)
    except (OSError, ValueError):
        return None
    return state if isinstance(state, dict) else None


def write_state(state):
    replace_file(home_file(STATE_NAME), (json.dumps(state, sort_keys=True) + "\n").encode("utf-8"), guard=False)


def journal_state(size, entries, counted=None):
    due, oldest = None, {}
    for _raw, _record, when, until, where in entries:
        due = until if due is None or until < due else due
        name = where or ""
        if name not in oldest or when < oldest[name]:
            oldest[name] = when
    return {"size": size, "due": due.strftime(STAMP) if due else None,
            "oldest": dict((name, when.strftime(STAMP)) for name, when in oldest.items()), "counted": counted or {}}


def pending_files():
    folder = home_file(PENDING_NAME)
    try:
        return sorted(os.path.join(folder, n) for n in os.listdir(folder) if n.endswith(".jsonl"))
    except OSError:
        return []


def write_pending(record):
    """A record that could not have the journal's lock in time: a file of its own in journal.pending/, written whole
    beside it and renamed into place, with an id, so the next tend adds it to the journal exactly once."""
    folder = home_file(PENDING_NAME)
    if not os.path.isdir(folder):
        os.makedirs(folder, mode=0o700, exist_ok=True)
        owner_only(folder, folder=True)
    record = dict(record, id=secrets.token_hex(8))
    handle, tmp = tempfile.mkstemp(prefix=".pending-", dir=folder)
    try:
        with os.fdopen(handle, "wb") as out:
            out.write((json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8"))
        os.replace(tmp, os.path.join(folder, "%s-%s.jsonl" % (record["time"].replace(":", ""), record["id"])))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def append_record(record, days, where, counted_kinds=()):
    """One record at the end of the journal, under its lock, and the journal's state brought up to date. A record that
    cannot have the lock within LOCK_WAIT seconds goes to journal.pending/ - never into the journal behind the lock's
    back, where a rewrite would lose it. -> whether the journal wants a tend now: a record past its period, a line
    gatecall did not write (an older gatecall still installed, a hand edit), a period shortened since the oldest record
    of this policy, a kind this policy keeps only as a count since its last pass, or records waiting in
    journal.pending/."""
    make_home()
    data = (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8")
    with file_lock(LOCK_NAME, LOCK_WAIT) as held:
        if not held:
            write_pending(record)
            return True
        path = journal_path()
        handle = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | BINARY, 0o600)
        with os.fdopen(handle, "ab") as out:
            before = os.fstat(out.fileno()).st_size
            out.write(data)
            out.flush()
            after = os.fstat(out.fileno()).st_size
        if before == 0:
            owner_only(path)
        now = utcnow()
        state = read_state() or {}
        foreign = state.get("size") != before
        due = parse_stamp(state.get("due"))
        oldest = dict(state["oldest"]) if isinstance(state.get("oldest"), dict) else {}
        first = parse_stamp(oldest.get(where or ""))
        shortened = first is not None and first + datetime.timedelta(days=days) <= now
        until = parse_stamp(record["keep_until"])
        oldest.setdefault(where or "", record["time"])
        known = dict(state["counted"]) if isinstance(state.get("counted"), dict) else {}
        recount = bool(set(counted_kinds) - set(strings(known.get(where or ""))))
        known[where or ""] = sorted(counted_kinds)
        write_state({"size": after, "due": (until if due is None or until < due else due).strftime(STAMP),
                     "oldest": oldest, "counted": known})
        return foreign or (due is not None and due <= now) or shortened or recount or bool(pending_files())


def tend_lines(raws, policies, now):
    """-> ([(line, record, time, due, policy file)], whether any line changed): the lines of the journal kept to the
    rules of each record's own folder."""
    out, changed = [], False
    for raw in raws:
        record, when = parse_record(raw.decode("utf-8", "replace"))
        if record is None:
            changed = True
            continue
        policy, where = policies.of(record.get("cwd"), session_policy(record))
        until = expiry(record, when, policy, where)
        if until <= now:
            changed = True
            continue
        if "key_id" not in record:
            record = with_session(sign_legacy(record, policies.key(policy, where), counted_for(policy)))
            raw = (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8")
            changed = True
        else:
            kept = keep_count_only(record, counted_for(policy))
            if kept is not None:
                record, raw, changed = kept, (json.dumps(kept, ensure_ascii=False) + "\n").encode("utf-8"), True
            elif not raw.endswith(b"\n"):
                raw, changed = raw + b"\n", True
        out.append((raw, record, when, until, where))
    return out, changed


def tend_journal(wait=0.0):
    """The journal kept to the rules of the folder each record was written in and of the session that wrote it (its
    $COMPANY_AI_POLICY, see session_policy), whichever folder and session this runs from: a
    record past its folder's retention period is deleted, a line that is not a record too, a record from before 0.1.4
    is signed again (sign_legacy), a record holding a kind its folder keeps only as a count now loses its fingerprints
    (keep_count_only), and the records waiting in journal.pending/ join the journal. The pass reads the
    journal without its lock; only its last step - the lines added meanwhile, the new file put in place - takes the
    lock, for milliseconds, so a hook never waits on a pass. -> False when another pass is running (it does the work)."""
    if not os.path.isdir(gatecall_home()):
        return True
    with file_lock(TEND_LOCK_NAME, wait) as tending:
        if not tending:
            return False
        path = journal_path()
        policies = Policies()
        now = utcnow()
        try:
            with open(path, "rb") as handle:
                data = handle.read()
        except FileNotFoundError:
            data = b""
        done = data.rfind(b"\n") + 1        # whole lines only: a line being written comes with the tail
        lines, changed = tend_lines(data[:done].splitlines(True), policies, now)
        with file_lock(LOCK_NAME, LOCK_WAIT) as held:
            if not held:
                return False
            try:
                with open(path, "rb") as handle:
                    handle.seek(done)
                    tail = handle.read()
            except FileNotFoundError:
                tail = b""
            more, grew = tend_lines(tail.splitlines(True), policies, now)
            lines += more
            seen = set(r.get("id") for _l, r, _w, _u, _p in lines if isinstance(r.get("id"), str))
            waiting, joined = pending_files(), []
            for name in waiting:
                try:
                    with open(name, "rb") as handle:
                        for raw in handle.read().splitlines(True):
                            record, _when = parse_record(raw.decode("utf-8", "replace"))
                            if record is not None and record.get("id") not in seen:
                                seen.add(record.get("id"))
                                joined.append(raw if raw.endswith(b"\n") else raw + b"\n")
                except OSError:
                    continue
            lines += tend_lines(joined, policies, now)[0]
            body = b"".join(raw for raw, _r, _w, _u, _p in lines)
            rewrite = changed or grew or bool(waiting)
            if rewrite:
                replace_file(path, body)
            counted = dict((where or "", sorted(counted_for(policy))) for policy, where in policies.seen.values())
            write_state(journal_state(len(body) if rewrite else done + len(tail), lines, counted))
            for name in waiting:
                try:
                    os.unlink(name)
                except OSError:
                    pass
    return True


def tend_now(wait):
    """tend_journal for a person waiting on it. Whatever stops it, what is shown stays right: a record past its period
    is never shown, and an unkeyed fingerprint never."""
    try:
        return tend_journal(wait)
    except (OSError, ValueError):
        return False


def tend_in_background():
    """A pass over the journal (the tend command) in a process of its own, cut loose from the hook - its own session,
    no handle of the hook's - so the hook answers at once and Claude Code never waits on the pass. -> the process, or
    None. Never raises."""
    try:
        options = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
        if WINDOWS:
            options["creationflags"] = (getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
                                        | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200))
        else:
            options["start_new_session"] = True
        return subprocess.Popen([sys.executable, os.path.abspath(__file__), "tend"], **options)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def write_journal(policy, event, tool, findings, rules_hit, cwd, key=None, where=None):
    """One line for one stop: the time, the folder, the kinds and the rules, a fingerprint of each value under the
    company's key - or only how many there were, for the kinds the company keeps as a count - and keep_until, the end
    of its retention period. Only an append: when the journal wants a tend, a pass starts in the background. Never
    raises: the stop stands whatever happens to its line."""
    if (policy or {}).get("journal") is False:
        return
    try:
        now = utcnow()
        counted_kinds = count_only(policy)[0]
        signed = [f for f in findings if f["kind"] not in counted_kinds]
        record = {"time": now.strftime(STAMP), "event": event, "tool": tool, "cwd": cwd,
                  "kinds": sorted(set(f["kind"] for f in findings)),
                  "fingerprints": sorted(set(f["fingerprint"] for f in signed if f.get("fingerprint"))),
                  "rules": sorted(set(rules_hit))}
        record["key_id"] = key.name() if record["fingerprints"] else None
        counted = {}
        for f in findings:
            if f["kind"] in counted_kinds:
                counted[f["kind"]] = counted.get(f["kind"], 0) + int(f.get("count") or 1)
        if counted:
            record["counted"] = counted
        if key is not None and key.problem:
            record["key_problem"] = key.problem
        with_session(record)
        days = retention_days(policy)
        record["keep_until"] = (now + datetime.timedelta(days=days)).strftime(STAMP)
        if append_record(record, days, where, counted_kinds):
            tend_in_background()
    except Exception:  # the stop stands; a journal that cannot be written is not a reason to let anything through
        pass


def read_journal(days=None):
    """The kept records, oldest first; those of the last `days` days when given. Until the next tend, what is shown
    keeps to each folder's rules all the same: a record past its retention period is never shown, a record from before
    0.1.4 never shows its unkeyed fingerprints, and a record of a kind moved to a count never shows its fingerprints.
    The records waiting in journal.pending/ are shown with the rest. A journal that is there and cannot be read is a
    Problem, never an empty journal."""
    policies = Policies()
    now = utcnow()
    start = since(days) if days else None
    raws = []
    for name in [journal_path()] + pending_files():
        try:
            with open(name, "rb") as handle:
                raws += handle.read().splitlines()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise Problem("cannot read the journal %s: %s" % (name, exc.strerror or exc))
    out, ids = [], set()
    for raw in raws:
        record, when = parse_record(raw.decode("utf-8", "replace"))
        if record is None or (start is not None and when < start):
            continue
        policy, where = policies.of(record.get("cwd"), session_policy(record))
        if expiry(record, when, policy, where) <= now:
            continue
        if isinstance(record.get("id"), str):
            if record["id"] in ids:
                continue
            ids.add(record["id"])
        if "key_id" not in record:
            record = dict(record, fingerprints=[], key_id=None)
        else:
            record = keep_count_only(record, counted_for(policy)) or record
        out.append(record)
    out.sort(key=lambda r: r["time"])
    return out


def repeats(records):
    """{(field, key name): how many values were stopped more than once}. A fingerprint is compared only with those of
    its own field and its own key: the new ones and the legacy ones are never mixed, nor two keys."""
    seen = {}
    for record in records:
        name = record.get("key_id") if isinstance(record.get("key_id"), str) else None
        for field in ("fingerprints", "legacy_fingerprints"):
            group = seen.setdefault((field, name), {})
            for mark in set(strings(record.get(field))):
                group[mark] = group.get(mark, 0) + 1
    out = {}
    for group, marks in seen.items():
        again = sum(1 for n in marks.values() if n > 1)
        if again:
            out[group] = again
    return out


def journal_lines(records, days, policy, key):
    """The journal as a person reads it: stops by kind and rule, what was kept only as a count, the values stopped
    more than once, and what to fix about the key."""
    lines = ["gatecall journal: %d stop(s) in %d day(s); records are kept %d day(s)"
             % (len(records), days, retention_days(policy))]
    counts, counted, problems = {}, {}, {}
    for record in records:
        for item in set(strings(record.get("kinds"))) | set(strings(record.get("rules"))):
            counts[item] = counts.get(item, 0) + 1
        values = record.get("counted") if isinstance(record.get("counted"), dict) else {}
        for kind, n in values.items():
            if isinstance(n, int):
                counted[kind] = counted.get(kind, 0) + n
        if isinstance(record.get("key_problem"), str):
            problems[record["key_problem"]] = problems.get(record["key_problem"], 0) + 1
    for item in sorted(counts):
        lines.append("  %s: %d" % (item, counts[item]))
    for kind in sorted(counted):
        lines.append("  %s kept only as a count: %d value(s)" % (kind, counted[kind]))
    for (field, name), n in sorted(repeats(records).items(), key=lambda item: (item[0][0], str(item[0][1]))):
        if field == "fingerprints":
            lines.append("  stopped more than once: %d value(s) under key %s" % (n, name))
        else:
            lines.append("  stopped more than once before 0.1.4: %d value(s) (legacy fingerprints, counted apart)" % n)
    for name in count_only(policy)[1]:
        lines.append("  journal_count_only: %s is not a kind (the kinds: %s)" % (name, ", ".join(detect.KINDS)))
    for problem in sorted(problems):
        lines.append("  no fingerprint in %d stop(s): %s" % (problems[problem], problem))
    note = guard_key(key.path) if os.path.isfile(key.path) else None
    if note:
        lines.append("  the journal's key: %s" % note)
    return lines


def csv_cell(value):
    """One CSV cell: a list joined by ';', counts as kind=n, nothing as empty; a cell a spreadsheet would run as a
    formula (= + - @ in front) starts with a quote and stays text."""
    if isinstance(value, dict):
        value = ";".join("%s=%s" % (k, v) for k, v in sorted(value.items()))
    elif isinstance(value, list):
        value = ";".join(str(v) for v in value)
    elif value is None:
        value = ""
    value = str(value)
    return "'" + value if value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


def write_export(records, out, form):
    if form == "csv":
        table = csv.writer(out)
        table.writerow(EXPORT_FIELDS)
        for record in records:
            table.writerow([csv_cell(record.get(field)) for field in EXPORT_FIELDS])
        return
    for record in records:
        out.write(json.dumps(record, ensure_ascii=False) + "\n")


def export_journal(records, target, form):
    """The kept records for the company's security team: JSON Lines, each record as kept, or CSV, a row a record with
    the new and the legacy fingerprints in their own columns. The file is readable by its owner only, as the
    journal is; "-" writes to the screen."""
    if target == "-":
        write_export(records, sys.stdout, form)
        return
    try:
        handle = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | BINARY, 0o600)
        with os.fdopen(handle, "w", encoding="utf-8", newline="") as out:
            write_export(records, out, form)
        if os.path.isfile(target):
            owner_only(target)              # a file that was there before is the owner's only too
    except OSError as exc:
        raise Problem("cannot write %s: %s" % (target, exc.strerror or exc))


# ---------------------------------------------------------------- what is said ------------------

def describe(findings, words):
    kinds = words.get("kinds") or {}
    parts = []
    for f in findings:
        parts.append("%s (%s)" % (kinds.get(f["kind"], f["kind"]), f["sample"]))
    return "; ".join(parts)


def block_text(words, key, findings, problems):
    lines = []
    if findings:
        lines.append(say(words, key, found=describe(findings, words)))
        lines.append(say(words, "advice"))
    for _code, text in problems:
        lines.append(text)
    return " ".join(lines)


# ---------------------------------------------------------------- hooks -------------------------

def hook_start(payload, env):
    policy, where = read_policy(None, payload.get("cwd"))
    rules = context(policy)
    if os.path.exists(journal_path()) or pending_files():
        tend_in_background()                # every session start: a policy changed since is kept to as well
    words = lang_words(pick_lang(policy, env))
    route = session_route(env)
    lines = [say(words, "start_line", profiles=", ".join(rules["names"]),
                 red=len(folders(policy, "red_paths")), policy=where or say(words, "no_policy"))]
    problems = denied_route(route, rules, words)
    if problems:
        lines.append(say(words, "start_denied_route", what=route["host"] or ", ".join(route["models"]),
                         profile=", ".join(rules["names"])))
    elif red_window(route, env):
        lines.append(say(words, "start_local", host=route["host"]))
    return " ".join(lines)


def hook_prompt(payload, env):
    cwd = payload.get("cwd") or os.getcwd()
    policy, where = read_policy(None, cwd)
    rules = context(policy)
    words = lang_words(pick_lang(policy, env))
    route = session_route(env)
    problems = denied_route(route, rules, words)
    key = journal_key(policy, where)
    findings = [] if route["local"] else findings_in(payload.get("prompt") or "", rules, key)
    if not findings and not problems:
        return None
    write_journal(policy, "prompt", None, findings, [c for c, _t in problems] + [f["kind"] for f in findings], cwd,
                  key, where)
    return {"decision": "block", "reason": block_text(words, "block_prompt", findings, problems)}


def tool_text(tool, data):
    if tool in ("Bash", "PowerShell"):
        return str(data.get("command") or "")
    if tool == "WebFetch":
        return "%s\n%s" % (data.get("url") or "", data.get("prompt") or "")
    if tool == "WebSearch":
        return str(data.get("query") or "")
    return json.dumps(data, ensure_ascii=False)


def tool_paths(tool, data, cwd):
    out = []
    if tool in FILE_TOOLS:
        for key in ("file_path", "notebook_path"):
            if isinstance(data.get(key), str) and data[key]:
                out.append(resolve_path(data[key], cwd))
    elif tool in SEARCH_TOOLS:
        out.append(resolve_path(data.get("path") or ".", cwd))
    return out


def own_hit(tool, data, text, cwd, policy, where):
    """The first of gatecall's own files a step opens, searches or names - its folder (the journal, its state and
    locks, the key beside it) and the key the policy names - or None. They are gatecall's alone in every window: the
    company's key never reaches a model, and no stop is erased. gatecall's own commands (journal, scan) read them."""
    places = [os.path.abspath(gatecall_home()), key_path(policy, where)]
    real = [os.path.realpath(p) for p in places]
    paths = command_paths(text, cwd) + [cwd] if tool == "Bash" else tool_paths(tool, data, cwd)
    for path in paths:
        if under(path, real):
            return path
    named = []
    if tool in ("Bash", "PowerShell") or tool.startswith("mcp__"):
        named.append(text)
    elif tool == "Glob":
        named.append(str(data.get("pattern") or ""))
    elif tool == "Grep":
        named.append(str(data.get("glob") or ""))
    for words in named:
        for path in places + real:
            for form in (path, json.dumps(path)[1:-1]):
                if re.search(re.escape(form) + r"(?![\w.-])", words):
                    return path
        if OWN_NAME.search(words) or any(form % name in words for name in OWN_VARS
                                         for form in ("$%s", "${%s}", "%%%s%%", "$env:%s")):
            return places[0]
    return None


def hook_tool(payload, env):
    tool = str(payload.get("tool_name") or "")
    data = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}
    cwd = payload.get("cwd") or os.getcwd()
    policy, where = read_policy(None, cwd)
    rules = context(policy)
    words = lang_words(pick_lang(policy, env))
    route = session_route(env)
    problems = list(denied_route(route, rules, words))
    findings = []
    key = journal_key(policy, where)
    red = folders(policy, "red_paths")
    opened = red_window(route, env)
    if red and not opened:
        paths = tool_paths(tool, data, cwd)
        if tool == "Bash":
            paths = command_paths(tool_text(tool, data), cwd) + [cwd]
        for path in paths:
            if under(path, red):
                problems.append(("red-folder", say(words, "red_path", path=path)))
                break
    text = tool_text(tool, data)
    own = own_hit(tool, data, text, cwd, policy, where)
    if own:
        problems.append(("gatecall-own-file", say(words, "own_file", path=own)))
    if opened:
        # The red window opens the red folders because nothing in it leaves this computer: no web tool, and a
        # network program only to this computer.
        far = [tool] if tool in OUTGOING_TOOLS else (outside_hosts(text, cwd) if tool == "Bash" else [])
        if far:
            problems.append(("red-window-offline", say(words, "red_offline", what=", ".join(far))))
    if tool == "Bash" or tool in OUTGOING_TOOLS or tool.startswith("mcp__"):
        problems.extend(denied_targets(tool, data, text, rules, words))
        if tool != "Bash" or not route["local"]:
            findings = findings_in(text, rules, key)
    if tool == "Bash":
        problems.extend(program_problems(text, cwd, policy, rules, words))
    if tool in ("Write", "Edit", "MultiEdit"):
        target = str(data.get("file_path") or "")
        pieces = [data.get("content"), data.get("new_string")]
        pieces += [e.get("new_string") for e in data.get("edits") or [] if isinstance(e, dict)]
        body = "\n".join(p for p in pieces if isinstance(p, str))
        if "antigravity" in target and target.endswith("settings.json") and BLANKET.search(body):
            problems.append(("agy-no-blanket-allow", say(words, "agy")))
        if os.path.basename(target) in (TRAINING_MARK, COPY_MARK):
            problems.append(("mark-by-person", say(words, "mark_by_person")))
    if not findings and not problems:
        return None
    write_journal(policy, "tool", tool, findings, [c for c, _t in problems] + [f["kind"] for f in findings], cwd, key,
                  where)
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                   "permissionDecisionReason": block_text(words, "block_tool", findings, problems)}}


def known_keys(policy, where):
    """The journal keys a step in this folder could reach - the one its policy names, $GATECALL_KEY_FILE's, the one
    beside the journal - each as its text. Read, never made."""
    out = []
    for path in sorted(set((key_path(policy, where), key_path({}), home_file(KEY_NAME)))):
        try:
            key = load_key(path)
        except OSError:
            continue
        if key and len(key) >= KEY_MIN:
            out.append(key.decode("utf-8", "replace"))
    return out


def text_leaves(value):
    """Every string inside a tool's result, however deep."""
    if isinstance(value, str):
        return [value]
    items = value.values() if isinstance(value, dict) else value if isinstance(value, list) else []
    return [text for item in items for text in text_leaves(item)]


def output_text(result):
    """A tool's result as the model reads it: a command's output and errors, the text of a file or of a search;
    anything else as JSON."""
    if isinstance(result, str):
        return result
    if isinstance(result, dict):
        if isinstance(result.get("stdout"), str) or isinstance(result.get("stderr"), str):
            return "\n".join(p for p in (result.get("stdout"), result.get("stderr")) if isinstance(p, str) and p)
        inner = result.get("file") if isinstance(result.get("file"), dict) else result
        if isinstance(inner.get("content"), str):
            return inner["content"]
    return json.dumps(result, ensure_ascii=False, indent=1)


def output_reply(tool, text, note=None):
    """What a PostToolUse hook answers to put `text` in place of a tool's output: updatedToolOutput, or for an MCP tool
    updatedMCPToolOutput."""
    out = {"hookEventName": "PostToolUse"}
    if tool.startswith("mcp__"):
        out["updatedMCPToolOutput"] = {"content": [{"type": "text", "text": text}]}
    else:
        out["updatedToolOutput"] = text
    if note:
        out["additionalContext"] = note
    return {"hookSpecificOutput": out}


def hook_output(payload, env):
    """After a command, a file read, a search or an MCP tool has run: a step that reached the company's journal key
    without naming it - a search over a folder that holds it, a script that opens it - had nothing in its input to stop.
    The key is taken out of its output before the model reads it (Claude Code's updatedToolOutput), case and place
    whatever, the rest of the output is left as it is, and the stop is journaled."""
    tool = str(payload.get("tool_name") or "")
    result = payload.get("tool_output", payload.get("tool_response"))
    if result is None:
        return None
    cwd = payload.get("cwd") or os.getcwd()
    policy, where = read_policy(None, cwd)
    leaves = [text.lower() for text in text_leaves(result)]
    found = [key for key in known_keys(policy, where) if any(key.lower() in text for text in leaves)]
    if not found:
        return None
    text = output_text(result)
    if not any(key.lower() in text.lower() for key in found):
        text = json.dumps(result, ensure_ascii=False, indent=1)        # the key sits in a part the text leaves out
    for key in found:
        text = re.sub(re.escape(key), OUTPUT_MARK, text, flags=re.I)
    write_journal(policy, "output", tool, [], ["gatecall-key-in-output"], cwd, None, where)
    return output_reply(tool, text, say(lang_words(pick_lang(policy, env)), "own_output"))


def run_hook(kind, stdin=None, env=None):
    """-> (stdout text or None). Never raises: a hook must not break the person's session."""
    env = os.environ if env is None else env
    raw = (stdin if stdin is not None else sys.stdin.read()) or "{}"
    try:
        payload = json.loads(raw)
    except ValueError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    try:
        if kind == "start":
            return hook_start(payload, env)
        if kind == "prompt":
            out = hook_prompt(payload, env)
        elif kind == "output":
            out = hook_output(payload, env)
        else:
            out = hook_tool(payload, env)
        return json.dumps(out, ensure_ascii=False) if out else None
    except Exception as exc:  # the session goes on; the reason is kept for the person who checks
        write_journal({}, "error", kind, [], ["internal-error: %r" % (exc,)], payload.get("cwd"))
        return fail_closed(kind, payload, env)


def fail_closed(kind, payload, env):
    """A company whose policy says "fail_closed": true stops a message or a step the guard could not
    check, rather than letting it through; any other company's session goes on (the default)."""
    if kind == "start":
        return None
    try:
        policy, _where = read_policy(None, payload.get("cwd") or os.getcwd())
    except Exception:  # an unreadable policy: nothing says the company asked to stop
        return None
    if policy.get("fail_closed") is not True:
        return None
    reason = say(lang_words(pick_lang(policy, env)), "fail_closed")
    if kind == "prompt":
        return json.dumps({"decision": "block", "reason": reason}, ensure_ascii=False)
    if kind == "output":
        return json.dumps(output_reply(str(payload.get("tool_name") or ""), reason), ensure_ascii=False)
    return json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                              "permissionDecisionReason": reason}}, ensure_ascii=False)


# ---------------------------------------------------------------- commands for people ------------

def claude_path(path):
    """An absolute path as a Claude Code permission rule writes it: //Users/x, //c/Users/x on Windows."""
    drive = re.match(r"^([A-Za-z]):[\\/](.*)$", path)
    if drive:
        return "//%s/%s" % (drive.group(1).lower(), drive.group(2).replace("\\", "/").strip("/"))
    return "/" + "/" + path.replace("\\", "/").lstrip("/")


def rule_path(path):
    """A path as a permission rule writes it: ~/... inside the home folder, the same rule for every person; //...
    anywhere else."""
    home = os.path.expanduser("~").rstrip("\\/")
    if path.startswith(home + os.sep):
        return "~/" + path[len(home) + 1:].replace("\\", "/")
    return claude_path(path)


def settings_block(policy, rules, where=None):
    deny = []
    for folder in folders(policy, "red_paths", real=False):
        rule = claude_path(folder).rstrip("/")
        deny.append("Read(%s/**)" % rule)
        deny.append("Edit(%s/**)" % rule)
    # The journal's key, for Claude Code's own tools and, with the sandbox on, for every command it runs (its Read
    # rules join the sandbox's): gatecall's hooks run outside both and keep using it. gatecall's folder is closed to
    # edits, so no stop is erased even where its hooks do not run; the journal itself stays readable by gatecall's
    # journal command.
    key = rule_path(key_path(policy, where))
    deny.append("Read(%s)" % key)
    deny.append("Edit(%s)" % key)
    deny.append("Edit(%s/**)" % rule_path(os.path.abspath(gatecall_home())).rstrip("/"))
    keep = rules.get("keep_hosts") or ()
    for domain in sorted(rules["deny_hosts"]):
        deny.append("WebFetch(domain:%s)" % domain)
        # A deny rule has no exception in Claude Code: where the company keeps a more specific domain open
        # (dashscope-intl.aliyuncs.com in Singapore inside aliyuncs.com), the wildcard is left to the hook.
        if not any(host_matches(k, domain) for k in keep):
            deny.append("WebFetch(domain:*.%s)" % domain)
    return {"permissions": {"deny": deny}}


def route_lines(policy, rules, color=None):
    red = folders(policy, "red_paths", real=False)
    yellow = folders(policy, "yellow_paths", real=False)
    denied = sorted(rules["deny_hosts"]) + sorted(rules["deny_models"])
    lines = {
        "red": "red (%s): stays on this computer - the red window reads it (a model on this computer, routecall's "
               "profile local-red); every other session is kept out by gatecall's hook, and cloud sessions also by "
               "the deny rules (gatecall settings)" % (", ".join(red) or "none named"),
        "yellow": "yellow (%s): the company's own accounts only - Claude Team or Enterprise seats, where the "
                  "company owns the outputs, or an API with zero data retention; never a personal plan%s" % (
                      ", ".join(yellow) or "none named",
                      "; never " + ", ".join(denied) if denied else ""),
        "green": "green (everything else): any tool the company allows%s" % (
            "; never " + ", ".join(denied) if denied else ""),
    }
    order = [color] if color else ["red", "yellow", "green"]
    return [lines[c] for c in order]


def mask_text(text, rules):
    """-> (the text with every finding replaced by its kind and masked sample, the findings). A list of addresses
    or phone numbers is masked address by address, number by number - the way Presidio's anonymizer replaces."""
    found = findings_in(text, rules)
    if "card" in rules["block"]:
        found += detect.cards(text, skip=[f["span"] for f in found], pattern=detect.CARD_FIELD_RE)
    if not found:
        return text, []
    kinds = set(f["kind"] for f in found)
    marks = [(f["span"][0], f["span"][1], "[%s %s]" % (f["kind"], f["sample"]))
             for f in found if f["kind"] not in ("email-batch", "phone-batch")]
    mails = [m.span() for m in detect.EMAIL_RE.finditer(text)]
    if "email-batch" in kinds:
        marks += [(a, b, "[e-mail]") for a, b in mails]
    if "phone-batch" in kinds:
        skip = [[a, b] for a, b, _label in marks] + [[a, b] for a, b in mails]
        marks += [(span[0], span[1], "[phone]") for _digits, span in detect.phone_spans(text, skip)]
    pieces, at = [], 0
    for a, b, label in sorted(marks, key=lambda m: (m[0], -m[1])):
        if a < at:
            continue                        # inside a span already masked
        pieces.append(text[at:a])
        pieces.append(label)
        at = b
    pieces.append(text[at:])
    return "".join(pieces), found


def tally(found):
    out = {}
    for f in found:
        out[f["kind"]] = out.get(f["kind"], 0) + int(f.get("count") or 1)
    return out


def clean_office(data, target, rules):
    """An office document is a zip of XML parts: each part is masked like text. A number the document's own
    formatting splits in two cannot be masked in place - then the document stays out, named."""
    try:
        src = zipfile.ZipFile(io.BytesIO(data))
        parts = src.infolist()
    except (zipfile.BadZipFile, OSError, ValueError):
        return False, "an office document that does not open: its content cannot be checked"
    found_all = []
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as out:
        for info in parts:
            body = src.read(info.filename)
            if info.filename.lower().endswith(".xml"):
                text = body.decode("utf-8", "surrogateescape")
                clean, found = mask_text(text, rules)
                if findings_in(re.sub(r"<[^>]+>", "", clean), rules):
                    return False, "a number split by the document's formatting cannot be masked in place: " \
                                  "save the document as text and copy that"
                found_all += found
                body = clean.encode("utf-8", "surrogateescape")
            out.writestr(info, body)
    with open(target, "wb") as handle:
        handle.write(buf.getvalue())
    return True, tally(found_all)


def clean_file(source, target, rules):
    """One file into the cleaned copy. -> (copied, what): what is {kind: count} masked in it, or why it stayed out.
    The values themselves are written nowhere."""
    with open(source, "rb") as handle:
        data = handle.read()
    low = source.lower()
    if low.endswith(OFFICE_ZIP):
        return clean_office(data, target, rules)
    if low.endswith(NOT_TEXT) or b"\x00" in data[:TEXT_SNIFF]:
        return False, "not text: its content cannot be checked here - save it as text and copy that"
    try:
        text, codec = data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        text, codec = data.decode("latin-1"), "latin-1"     # an 8-bit text: digits and addresses read the same
    clean, found = mask_text(text, rules)
    if not found:
        shutil.copy2(source, target)
        return True, {}
    with open(target, "wb") as handle:
        handle.write(clean.encode(codec))
    shutil.copystat(source, target)
    return True, tally(found)


def make_copy(source, dest, policy):
    source = os.path.abspath(os.path.expanduser(source))
    dest = os.path.abspath(os.path.expanduser(dest))
    if not os.path.isdir(source):
        raise Problem("%s is not a folder" % source)
    if os.path.exists(dest) and (not os.path.isdir(dest) or os.listdir(dest)):
        raise Problem("%s must be a new or empty folder" % dest)
    red = folders(policy, "red_paths")
    if under(dest, [os.path.realpath(source)]):
        raise Problem("the copy cannot sit inside the folder it copies")
    rules = context(policy)
    copied = 0
    skipped = []
    why = {}
    masked = {}
    for folder, dirs, names in os.walk(source):
        keep = []
        for d in sorted(dirs):
            full = os.path.join(folder, d)
            if d in SKIP_IN_COPY or under(full, red):
                skipped.append(os.path.relpath(full, source) + "/")
            else:
                keep.append(d)
        dirs[:] = keep
        for name in sorted(names):
            full = os.path.join(folder, name)
            rel = os.path.relpath(full, source)
            if any(fnmatch.fnmatch(name, pattern) for pattern in SECRET_FILES) or under(full, red):
                skipped.append(rel)
                continue
            target = os.path.join(dest, rel)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            done, what = clean_file(full, target, rules)
            if not done:
                skipped.append(rel)
                why[rel] = what
                continue
            copied += 1
            if what:
                masked[rel] = what
    os.makedirs(dest, exist_ok=True)
    with open(os.path.join(dest, COPY_MARK), "w", encoding="utf-8") as handle:
        json.dump({"from": source, "made": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                   "copied": copied, "left_out": skipped, "why_left_out": why, "masked": masked},
                  handle, ensure_ascii=False, indent=1)
    return copied, skipped


def scan_item(finding, key, policy):
    """One finding as scan --json gives it: the fingerprint the journal would hold, with key_id - the id of the key it
    was made under, as every journal record names it - or, where the journal holds no fingerprint, none, and why: the
    company keeps the kind only as a count, or there is no key here to make it with."""
    item = dict((k, v) for k, v in finding.items() if k != "span")
    item["key_id"] = None
    if (policy or {}).get("journal") is False:
        item["fingerprint"] = None
        item["no_fingerprint"] = "the company policy turns the journal off"
    elif finding["kind"] in counted_for(policy):
        item["fingerprint"] = None
        item["no_fingerprint"] = "the company keeps %s only as a count: the journal holds no fingerprint of it" \
                                 % finding["kind"]
    elif item.get("fingerprint"):
        item["key_id"] = key.name()
    else:
        item["no_fingerprint"] = (key.problem if key is not None else None) or "no key"
    return item


def parser():
    top = argparse.ArgumentParser(prog="gatecall.py", description="What may leave the company. Sends nothing.")
    sub = top.add_subparsers(dest="command")
    one = sub.add_parser("hook")
    one.add_argument("kind", choices=("start", "prompt", "tool", "output"))
    one = sub.add_parser("scan")
    one.add_argument("file", nargs="?")
    one.add_argument("--profile", action="append")
    one.add_argument("--country")
    one.add_argument("--policy")
    one.add_argument("--json", action="store_true")
    one = sub.add_parser("settings")
    one.add_argument("--policy")
    one.add_argument("--out")
    one = sub.add_parser("route")
    one.add_argument("--color", choices=("red", "yellow", "green"))
    one.add_argument("--policy")
    one = sub.add_parser("copy")
    one.add_argument("source")
    one.add_argument("dest")
    one.add_argument("--policy")
    one = sub.add_parser("mark")
    one.add_argument("--training", required=True)
    one = sub.add_parser("journal")
    one.add_argument("--days", type=int)
    one.add_argument("--export", metavar="FILE")
    one.add_argument("--format", choices=("jsonl", "csv"), default="jsonl")
    one.add_argument("--policy")
    sub.add_parser("tend")
    sub.add_parser("profiles")
    return top


def run(argv):
    args = parser().parse_args(argv)
    if not args.command:
        parser().print_help()
        return 2
    if args.command == "hook":
        out = run_hook(args.kind)
        if out:
            print(out)
        return 0
    if args.command == "scan":
        policy, where = read_policy(args.policy)
        rules = context(policy, args.profile, args.country)
        if args.file:
            try:
                with open(args.file, encoding="utf-8", errors="replace") as handle:
                    text = handle.read()
            except OSError as exc:
                raise Problem("cannot read %s: %s" % (args.file, exc))
        else:
            text = sys.stdin.read()
        # --json carries each value's fingerprint under the company's key, named by its key_id as in the journal: a stop
        # in the journal matches its file. scan reads the key and never makes one.
        key = journal_key(policy, where, make=False) if args.json else None
        found = findings_in(text, rules, key)
        if args.json:
            print(json.dumps([scan_item(f, key, policy) for f in found], indent=2))
        else:
            for f in found:
                print("%s: %s (%s)" % (f["kind"], f["name"], f["sample"]))
            print("gatecall scan: %d thing(s) that would be stopped (profiles %s)" % (len(found), ", ".join(rules["names"])))
        return 1 if found else 0
    if args.command == "settings":
        policy, where = read_policy(args.policy)
        block = settings_block(policy, context(policy), where)
        text = json.dumps(block, indent=2)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as handle:
                handle.write(text + "\n")
            print("gatecall: the permissions block is in %s" % args.out)
        else:
            print(text)
        return 0
    if args.command == "route":
        policy, _where = read_policy(args.policy)
        for line in route_lines(policy, context(policy), args.color):
            print(line)
        return 0
    if args.command == "copy":
        policy, _where = read_policy(args.policy)
        copied, skipped = make_copy(args.source, args.dest, policy)
        print("gatecall: %d file(s) copied to %s; left out: %s" % (copied, args.dest, ", ".join(skipped) or "nothing"))
        mark = load_json(os.path.join(os.path.abspath(os.path.expanduser(args.dest)), COPY_MARK), "the copy's mark")
        for rel, kinds in sorted((mark.get("masked") or {}).items()):
            print("  masked in %s: %s" % (rel, ", ".join("%s x%d" % (k, n) for k, n in sorted(kinds.items()))))
        for rel, reason in sorted((mark.get("why_left_out") or {}).items()):
            print("  left out %s: %s" % (rel, reason))
        return 0
    if args.command == "mark":
        folder = os.path.abspath(os.path.expanduser(args.training))
        if not os.path.isdir(folder):
            raise Problem("%s is not a folder" % folder)
        policy, _where = read_policy(None, folder)
        if under(folder, folders(policy, "red_paths")):
            raise Problem("%s is in a red folder: practice files are made for practice, not taken from there" % folder)
        with open(os.path.join(folder, TRAINING_MARK), "w", encoding="utf-8") as handle:
            handle.write("practice files only - marked by a person on %s\n"
                         % datetime.date.today().isoformat())
        print("gatecall: %s is a training folder now" % folder)
        return 0
    if args.command == "journal":
        policy, where = read_policy(args.policy)
        tend_now(TEND_WAIT)
        # --export without --days gives every kept record: each folder's records are kept by its own policy
        days = max(1, args.days) if args.days else (None if args.export else min(7, retention_days(policy)))
        records = read_journal(days)
        if args.export:
            export_journal(records, args.export, args.format)
            if args.export != "-":
                print("gatecall: %d record(s)%s exported to %s (%s)"
                      % (len(records), " of %d day(s)" % days if days else "", args.export, args.format))
            return 0
        for line in journal_lines(records, days, policy, JournalKey(policy, where)):
            print(line)
        return 0
    if args.command == "tend":
        tend_now(TEND_WAIT)
        return 0
    if args.command == "profiles":
        doc = load_profiles()
        for name in sorted(doc["profiles"]):
            profile = doc["profiles"][name]
            print("%s: %s Why: %s" % (name, profile.get("about", ""), profile.get("why", "")))
        for name in sorted(doc.get("programs") or {}):
            program = doc["programs"][name]
            print("%s (%s): %s Why: %s" % (name, program.get("rule"), program.get("about", ""), program.get("why", "")))
        return 0
    return 2


def main(argv=None):
    try:
        return run(sys.argv[1:] if argv is None else argv)
    except Problem as exc:
        print("gatecall: %s" % exc)
        return 2
    except SystemExit as exc:          # argparse's own exits (--help, a bad flag)
        return exc.code if isinstance(exc.code, int) else 2
    except Exception as exc:           # a bug here must say so in one line, never a traceback
        print("gatecall: internal error: %r" % (exc,))
        return 2


if __name__ == "__main__":
    sys.exit(main())
