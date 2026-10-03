"""The language check: Cyrillic only in language places. Controls plant it and expect red."""
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("check_language", ROOT / "scripts" / "check_language.py")
check_language = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_language)

RU_WORD = "".join(chr(c) for c in (0x43F, 0x440, 0x438, 0x432, 0x435, 0x442))  # a Russian word, from code points


def test_repository_is_clean():
    files = check_language.plugin_files(ROOT)
    # positive control on the walk itself: it must see the plugin's own script and its Russian dictionary
    assert "skills/gatecall/scripts/gatecall.py" in files
    assert "lang/ru.json" in files
    assert check_language.violations(ROOT, files) == []


def _plant(tmp_path, name, text):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return name


def test_control_comment_in_code_is_red(tmp_path):
    name = _plant(tmp_path, "skills/x/scripts/tool.py", "x = 1  # %s\n" % RU_WORD)
    assert check_language.violations(tmp_path, [name])
    _plant(tmp_path, "skills/x/scripts/tool.py", "x = 1  # hello\n")
    assert check_language.violations(tmp_path, [name]) == []


def test_control_json_key_in_the_profiles_is_red(tmp_path):
    """A Russian context word typed into data/profiles.json would redden this: it belongs in lang/ru.json."""
    name = _plant(tmp_path, "data/profiles.json", json.dumps({"context": [RU_WORD]}, ensure_ascii=False))
    assert check_language.violations(tmp_path, [name])
    _plant(tmp_path, "data/profiles.json", json.dumps({"context": ["INN"]}))
    assert check_language.violations(tmp_path, [name]) == []


def test_language_places_are_allowed(tmp_path):
    names = [
        _plant(tmp_path, "README.ru.md", "%s\n" % RU_WORD),
        _plant(tmp_path, "lang/ru.json", json.dumps({"w": RU_WORD}, ensure_ascii=False)),
        _plant(tmp_path, "lang/uk.json", json.dumps({"w": RU_WORD}, ensure_ascii=False)),
        _plant(tmp_path, "tests/fixtures/ru/case.txt", "%s\n" % RU_WORD),
    ]
    assert check_language.violations(tmp_path, names) == []


def test_other_language_files_may_not_hold_cyrillic(tmp_path):
    name = _plant(tmp_path, "lang/es.json", json.dumps({"w": RU_WORD}, ensure_ascii=False))
    assert check_language.violations(tmp_path, [name])


def test_the_walk_skips_junk_folders(tmp_path):
    _plant(tmp_path, ".git/objects/x", "%s\n" % RU_WORD)
    _plant(tmp_path, "__pycache__/x.txt", "%s\n" % RU_WORD)
    _plant(tmp_path, "keep.txt", "hello\n")
    assert check_language.plugin_files(tmp_path) == ["keep.txt"]


# --- Tone: the product speaks of what it does. No disclaimers, excuses or apologies in what people read. ---
# LICENSE and NOTICE carry the legal minimum and are not read here. Russian, Ukrainian, Spanish and Portuguese phrases are written
# as escapes so this file stays ASCII (the language check above reads it too).
STOP_PHRASES = (
    "own risk", "no warranty", "without warranty", "not legal advice", "not financial advice",
    "not tax advice", "consult a lawyer", "consult your lawyer", "consult an accountant",
    "consult your accountant", "for educational purposes", "unfortunately", "honestly", "sorry",
    "we apologi", "disclaimer", "we don't know", "secondary source only", "for now", "can't yet",
    "\u043a \u0441\u043e\u0436\u0430\u043b\u0435\u043d\u0438\u044e",                      # ru: unfortunately
    "\u0447\u0435\u0441\u0442\u043d\u043e \u0433\u043e\u0432\u043e\u0440\u044f",          # ru: honestly speaking
    "\u043d\u0430 \u0441\u0432\u043e\u0439 \u0441\u0442\u0440\u0430\u0445",              # ru: at one's own risk
    "\u043f\u0440\u043e\u043a\u043e\u043d\u0441\u0443\u043b\u044c\u0442\u0438\u0440\u0443\u0439\u0442\u0435\u0441\u044c",  # ru: consult
    "\u0438\u0437\u0432\u0438\u043d\u0438\u0442\u0435",                                   # ru: sorry
    "\u043d\u0430 \u0436\u0430\u043b\u044c",                                             # uk: unfortunately
    "\u0432\u0438\u0431\u0430\u0447\u0442\u0435",                                         # uk: sorry
    "lamentablemente", "por desgracia", "bajo su propio riesgo",                          # es
    "infelizmente", "por sua conta e risco",                                              # pt
)


def tone_files(root):
    """What people and Claude read: READMEs, SECURITY.md, skills (text and scripts), dictionaries, hooks."""
    out = []
    for rel in check_language.plugin_files(root):
        name = rel.split("/")[-1]
        if (rel.startswith("README") or rel == "SECURITY.md" or rel.startswith("skills/")
                or (rel.startswith("lang/") and name.endswith(".json")) or rel.startswith("hooks/")):
            out.append(rel)
    return out


def tone_offenders(root, paths):
    found = []
    for rel in paths:
        text = (Path(root) / rel).read_text(encoding="utf-8", errors="replace").lower()
        for phrase in STOP_PHRASES:
            if phrase in text:
                found.append("%s: %r" % (rel, phrase))
    return found


def test_no_disclaimers_in_what_people_read():
    files = tone_files(ROOT)
    assert "README.md" in files and "lang/en.json" in files      # positive control on the selection
    assert tone_offenders(ROOT, files) == []


def test_control_a_planted_disclaimer_is_red(tmp_path):
    for phrase in ("Use at your own risk.", "This is not legal advice.", "Unfortunately we can't yet.", "It does nothing for now.",
                   "\u041a \u0441\u043e\u0436\u0430\u043b\u0435\u043d\u0438\u044e, \u043d\u0435\u0442."):
        name = _plant(tmp_path, "README.md", phrase + "\n")
        assert tone_offenders(tmp_path, [name]), phrase
    name = _plant(tmp_path, "README.md", "It stops, explains and shows the way forward.\n")
    assert tone_offenders(tmp_path, [name]) == []
