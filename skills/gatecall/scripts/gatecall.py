#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gatecall: what may leave the company, and where it may go. It stops; it never sends anything.

  gatecall.py hook start|prompt|tool
      The three hooks (hooks/hooks.json), the hook's JSON on stdin. start: one line naming the profile and
      the red folders. prompt: a message holding a key, a card, an IBAN, an ID number or a list of people
      is stopped before it leaves. tool: the same for commands, web requests and tool calls; red folders
      are read only by a model on this computer; kimi, grok and agy are kept to their rules.
  gatecall.py scan [FILE] [--profile P ...] [--country CC] [--policy FILE] [--json]
      What in a file (or stdin) would be stopped, masked. Exit 1 when something would.
  gatecall.py settings [--policy FILE] [--out FILE]
      The permissions.deny block for Claude Code: Read and Edit of every red folder by its absolute
      //path, and WebFetch of the hosts the profile denies.
  gatecall.py route [--color red|yellow|green] [--policy FILE]
      Where each colour of data may go, from the company's policy and profiles.
  gatecall.py copy SOURCE DEST [--policy FILE]
      A cleaned copy for an agent that works only on copies: no red folder, no key file, no .git.
  gatecall.py mark --training FOLDER
      A person marks a folder of practice files as a training folder.
  gatecall.py journal [--days N]
      What was stopped, by kind and rule - never the values themselves.
  gatecall.py profiles
      The profiles and the program rules, with their reasons.

Standard library only, no network. Exit 0: fine. 1: something would be stopped. 2: bad input.
A hook never fails the session: an internal error is written to the journal and the step goes on.
"""
import argparse
import datetime
import fnmatch
import io
import json
import os
import re
import shlex
import shutil
import sys
import zipfile

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

def policy_paths(cwd=None):
    """Where company-ai-policy.json is looked for, the binding one first: the managed copy an
    administrator installed, then $COMPANY_AI_POLICY, then the project, then the person's own."""
    out = []
    managed = MANAGED_DIRS.get(sys.platform)
    if managed:
        out.append(os.path.join(managed, POLICY_NAME))
    env = os.environ.get("COMPANY_AI_POLICY")
    if env:
        out.append(env)
    base = cwd or os.getcwd()
    out.append(os.path.join(base, POLICY_NAME))
    out.append(os.path.join(base, ".claude", POLICY_NAME))
    out.append(os.path.join(os.path.expanduser("~"), ".claude", POLICY_NAME))
    return out


def read_policy(explicit=None, cwd=None):
    """-> (policy dict, path) or ({}, None). A file that does not parse is a Problem, not silence."""
    for path in ([explicit] if explicit else policy_paths(cwd)):
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


def findings_in(text, rules):
    return [f for f in detect.scan(text, rules["ids"], rules["catalogue"], rules["email_batch"],
                                   rules["phone_batch"]) if f["kind"] in rules["block"]]


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

def journal_path():
    home = os.environ.get("GATECALL_HOME") or os.path.join(os.path.expanduser("~"), ".gatecall")
    return os.path.join(home, "journal.jsonl")


def write_journal(policy, event, tool, findings, rules_hit, cwd):
    if (policy or {}).get("journal") is False:
        return
    record = {"time": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
              "event": event, "tool": tool, "cwd": cwd,
              "kinds": sorted(set(f["kind"] for f in findings)),
              "fingerprints": sorted(set(f["fingerprint"] for f in findings)),
              "rules": sorted(set(rules_hit))}
    try:
        path = journal_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass


def read_journal(days=7):
    since = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
    out = []
    try:
        handle = open(journal_path(), encoding="utf-8")
    except OSError:
        return out
    with handle:
        for line in handle:
            try:
                record = json.loads(line)
                stamp = datetime.datetime.strptime(record["time"], "%Y-%m-%dT%H:%M:%SZ").replace(
                    tzinfo=datetime.timezone.utc)
            except (ValueError, KeyError, TypeError):
                continue
            if stamp >= since:
                out.append(record)
    return out


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
    policy, _where = read_policy(None, cwd)
    rules = context(policy)
    words = lang_words(pick_lang(policy, env))
    route = session_route(env)
    problems = denied_route(route, rules, words)
    findings = [] if route["local"] else findings_in(payload.get("prompt") or "", rules)
    if not findings and not problems:
        return None
    write_journal(policy, "prompt", None, findings, [c for c, _t in problems] + [f["kind"] for f in findings], cwd)
    return {"decision": "block", "reason": block_text(words, "block_prompt", findings, problems)}


def tool_text(tool, data):
    if tool == "Bash":
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


def hook_tool(payload, env):
    tool = str(payload.get("tool_name") or "")
    data = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}
    cwd = payload.get("cwd") or os.getcwd()
    policy, _where = read_policy(None, cwd)
    rules = context(policy)
    words = lang_words(pick_lang(policy, env))
    route = session_route(env)
    problems = list(denied_route(route, rules, words))
    findings = []
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
    if opened:
        # The red window opens the red folders because nothing in it leaves this computer: no web tool, and a
        # network program only to this computer.
        far = [tool] if tool in OUTGOING_TOOLS else (outside_hosts(text, cwd) if tool == "Bash" else [])
        if far:
            problems.append(("red-window-offline", say(words, "red_offline", what=", ".join(far))))
    if tool == "Bash" or tool in OUTGOING_TOOLS or tool.startswith("mcp__"):
        problems.extend(denied_targets(tool, data, text, rules, words))
        if tool != "Bash" or not route["local"]:
            findings = findings_in(text, rules)
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
    write_journal(policy, "tool", tool, findings, [c for c, _t in problems] + [f["kind"] for f in findings], cwd)
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                   "permissionDecisionReason": block_text(words, "block_tool", findings, problems)}}


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
    return json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                              "permissionDecisionReason": reason}}, ensure_ascii=False)


# ---------------------------------------------------------------- commands for people ------------

def claude_path(path):
    """An absolute path as a Claude Code permission rule writes it: //Users/x, //c/Users/x on Windows."""
    drive = re.match(r"^([A-Za-z]):[\\/](.*)$", path)
    if drive:
        return "//%s/%s" % (drive.group(1).lower(), drive.group(2).replace("\\", "/").strip("/"))
    return "/" + "/" + path.replace("\\", "/").lstrip("/")


def settings_block(policy, rules):
    deny = []
    for folder in folders(policy, "red_paths", real=False):
        rule = claude_path(folder).rstrip("/")
        deny.append("Read(%s/**)" % rule)
        deny.append("Edit(%s/**)" % rule)
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


def parser():
    top = argparse.ArgumentParser(prog="gatecall.py", description="What may leave the company. Sends nothing.")
    sub = top.add_subparsers(dest="command")
    one = sub.add_parser("hook")
    one.add_argument("kind", choices=("start", "prompt", "tool"))
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
    one.add_argument("--days", type=int, default=7)
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
        policy, _where = read_policy(args.policy)
        rules = context(policy, args.profile, args.country)
        if args.file:
            try:
                with open(args.file, encoding="utf-8", errors="replace") as handle:
                    text = handle.read()
            except OSError as exc:
                raise Problem("cannot read %s: %s" % (args.file, exc))
        else:
            text = sys.stdin.read()
        found = findings_in(text, rules)
        if args.json:
            print(json.dumps([dict((k, v) for k, v in f.items() if k != "span") for f in found], indent=2))
        else:
            for f in found:
                print("%s: %s (%s)" % (f["kind"], f["name"], f["sample"]))
            print("gatecall scan: %d thing(s) that would be stopped (profiles %s)" % (len(found), ", ".join(rules["names"])))
        return 1 if found else 0
    if args.command == "settings":
        policy, _where = read_policy(args.policy)
        block = settings_block(policy, context(policy))
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
        records = read_journal(max(1, args.days))
        counts = {}
        for record in records:
            for item in (record.get("kinds") or []) + (record.get("rules") or []):
                counts[item] = counts.get(item, 0) + 1
        print("gatecall journal: %d stop(s) in %d day(s)" % (len(records), max(1, args.days)))
        for item in sorted(counts):
            print("  %s: %d" % (item, counts[item]))
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
