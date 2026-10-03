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
