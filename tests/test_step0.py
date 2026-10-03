"""Step 0 guard (hooks/python.sh): a hook runs only with a real Python 3, and never starts a stub.

The trap it closes: a Mac without Apple's Command Line Tools has /usr/bin/python3, and running it
pops Apple's "install developer tools?" window - in the middle of a lesson, on every hook. On
Windows the trap is the Microsoft Store stub. Every case here builds a fake PATH, so it runs the
same on any machine. The launcher is the same file as in safecall (hooks/python.sh, python.ps1);
this plugin keeps its scripts in skills/<name>/scripts/ (a Cowork plugin has no bin/), which the
checks below accept as well as scripts/.
"""
import glob
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GUARD = os.path.join(ROOT, "hooks", "python.sh")
PLUGIN = json.load(open(os.path.join(ROOT, ".claude-plugin", "plugin.json")))["name"]
HOOKS = os.path.join(ROOT, "hooks", "hooks.json")
has_hooks = unittest.skipUnless(os.path.exists(HOOKS), "this plugin has no hooks, only the launcher for its skills")
SKILLS = sorted(glob.glob(os.path.join(ROOT, "skills", "*", "SKILL.md")))
SH = 'sh "${CLAUDE_PLUGIN_ROOT}/hooks/python.sh" %s say ' % PLUGIN
# PowerShell: the launcher's path bare - Claude Code checks a `& "..."` call as an operation it cannot read and
# asks for it whatever the rule says (2.1.288), while a bare path is matched against the rule like any command.
PS = '${CLAUDE_PLUGIN_ROOT}/hooks/python.ps1 %s say ' % PLUGIN
SCRIPT_PATH = r"((?:skills/[\w.-]+/)?scripts/[\w.-]+\.py)"
# gatecall's session-start hook speaks: with no Python the person must hear that the data guard is off. The
# message and step hooks stay quiet, so the step-0 line is said once per session, not at every turn.
SAYING_HOOKS = 1
# a non-English word (the hook JSON is UTF-8), built from code points so this file stays ASCII
WORD = "".join(chr(c) for c in (0x43F, 0x440, 0x438, 0x432, 0x435, 0x442))


def tool(folder, name, body):
    path = os.path.join(folder, name)
    with open(path, "w") as fh:
        fh.write("#!/bin/sh\n" + body + "\n")
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def hook_commands():
    hooks = json.load(open(HOOKS))["hooks"]
    return [h["command"] for groups in hooks.values() for g in groups for h in g["hooks"]]


class StepZero(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.bin = os.path.join(self.tmp, "bin")
        os.mkdir(self.bin)
        self.ran = os.path.join(self.tmp, "RAN")
        self.script = os.path.join(self.tmp, "hook.py")
        open(self.script, "w").write("print('hook ran')\n")
        # The minimum a shell needs, and nothing called python.
        for name in ("uname", "cat", "echo", "true"):
            for d in ("/usr/bin", "/bin"):
                if os.path.exists(os.path.join(d, name)):
                    os.symlink(os.path.join(d, name), os.path.join(self.bin, name))
                    break

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_guard(self, mode, env_extra):
        env = {"PATH": self.bin, "HOME": self.tmp}
        env.update(env_extra)
        p = subprocess.run(["/bin/sh", GUARD, PLUGIN, mode, self.script], env=env,
                           capture_output=True, text=True, timeout=20)
        return p.returncode, p.stdout, p.stderr

    def fake_python(self, name, works=True):
        # Records every run, so a test can prove a stub was never started.
        exit_code = 0 if works else 9009
        return tool(self.bin, name, 'echo x >> "%s"\n[ "$1" = -c ] && exit %d\nexec "%s" "$@"'
                    % (self.ran, exit_code, os.path.realpath(subprocess.check_output(
                        ["/bin/sh", "-c", "command -v python3"], text=True).strip())))

    def test_mac_without_command_line_tools_never_starts_the_apple_stub(self):
        stub = self.fake_python("python3")
        tool(self.bin, "xcode-select", "exit 2")
        for mode, said in (("say", True), ("quiet", False)):
            code, out, err = self.run_guard(mode, {"STEP0_OS": "Darwin", "STEP0_APPLE_STUB": stub})
            self.assertEqual(code, 0)
            self.assertFalse(os.path.exists(self.ran), "the Apple stub was started")
            self.assertEqual("paused" in out, said, out)
            if said:
                self.assertIn("xcode-select --install", out)
                self.assertEqual(len(out.strip().splitlines()), 1)

    def test_mac_with_command_line_tools_runs_the_hook(self):
        stub = self.fake_python("python3")
        dev = os.path.join(self.tmp, "CommandLineTools")
        os.makedirs(os.path.join(dev, "usr", "bin"))
        tool(os.path.join(dev, "usr", "bin"), "python3", "exit 0")
        tool(self.bin, "xcode-select", 'echo "%s"' % dev)
        code, out, err = self.run_guard("say", {"STEP0_OS": "Darwin", "STEP0_APPLE_STUB": stub})
        self.assertEqual((code, out.strip()), (0, "hook ran"), err)

    def test_mac_with_another_python_first_needs_no_command_line_tools(self):
        self.fake_python("python3")          # not the stub path, e.g. Homebrew or python.org
        tool(self.bin, "xcode-select", "exit 2")
        code, out, err = self.run_guard("say", {"STEP0_OS": "Darwin", "STEP0_APPLE_STUB": "/usr/bin/python3"})
        self.assertEqual((code, out.strip()), (0, "hook ran"), err)

    def test_windows_store_stub_is_skipped_and_python_is_found(self):
        self.fake_python("python3", works=False)   # the Microsoft Store alias
        self.fake_python("python")                 # python.org's name on Windows
        code, out, err = self.run_guard("say", {"STEP0_OS": "MINGW64_NT-10.0"})
        self.assertEqual((code, out.strip()), (0, "hook ran"), err)

    def test_no_python_at_all_is_one_line_and_exit_zero(self):
        self.fake_python("python3", works=False)
        code, out, err = self.run_guard("say", {"STEP0_OS": "Linux"})
        self.assertEqual(code, 0)
        self.assertIn("paused", out)
        self.assertEqual(self.run_guard("quiet", {"STEP0_OS": "Linux"})[:2], (0, ""))

    @has_hooks
    def test_every_hook_goes_through_the_guard(self):
        commands = hook_commands()
        self.assertTrue(commands)
        sh_line = 'exec sh "${CLAUDE_PLUGIN_ROOT}/hooks/python.sh" %s ' % PLUGIN
        # `trap` is hoisted to the top of its scope, so it also silences PowerShell's "exec is not recognized"
        # for the first line - which would otherwise stand in front of a guard's reason when it blocks.
        ps_line = ('trap { continue }; '
                   '& ([scriptblock]::Create((Get-Content -Raw -LiteralPath "${CLAUDE_PLUGIN_ROOT}/hooks/python.ps1")))'
                   ' %s ' % PLUGIN)
        for c in commands:
            # Two lines, one per kind of shell: sh and Git Bash run the first (`exec` never comes back), PowerShell
            # - Windows without Git Bash - finds no `exec`, goes on, and runs the second. Same arguments in both.
            first, second = c.split("\n")
            self.assertTrue(first.startswith(sh_line), first)
            self.assertTrue(second.startswith(ps_line), second)
            self.assertEqual(first[len(sh_line):], second[len(ps_line):])
            script = re.search(r'"\$\{CLAUDE_PLUGIN_ROOT\}/([^"]+\.py)"', first)
            self.assertIsNotNone(script, first)
            self.assertTrue(os.path.exists(os.path.join(ROOT, script.group(1))), script.group(1))
        self.assertEqual(sum(" say " in c for c in commands), SAYING_HOOKS)

    @has_hooks
    def test_each_command_runs_in_sh_to_the_end_of_its_first_line_only(self):
        """sh must never read the PowerShell line: `exec` hands the process to python.sh, and its exit code is the
        hook's."""
        command = hook_commands()[0]
        fake_root = os.path.join(self.tmp, "root")
        os.makedirs(os.path.join(fake_root, "hooks"))
        tool(os.path.join(fake_root, "hooks"), "python.sh", 'echo "args: $*"; exit 2')
        p = subprocess.run(["/bin/sh", "-c", command], env={"PATH": os.environ["PATH"], "CLAUDE_PLUGIN_ROOT": fake_root},
                           capture_output=True, text=True, timeout=20)
        self.assertEqual(p.returncode, 2, p.stderr)
        self.assertTrue(p.stdout.startswith("args: %s " % PLUGIN), p.stdout)
        self.assertEqual(p.stderr, "")

    def test_the_powershell_twin_is_plain_ascii_and_says_the_same_line(self):
        ps1 = open(os.path.join(ROOT, "hooks", "python.ps1"), "rb").read()
        ps1.decode("ascii")                      # Windows PowerShell 5.1 reads a file without a BOM as ANSI
        sh = open(GUARD).read()
        said = sh.split('echo "$plugin is paused:', 1)[1].split('"', 1)[0]
        self.assertIn(said, ps1.decode())

    def test_the_launcher_is_safecalls_own(self):
        """One launcher for every Poly A1 plugin: when safecall's copy is on this computer, the two are the same
        file (a fix made there must not be missed here)."""
        theirs = os.path.join(os.path.expanduser("~"), "Developer", "safecall", "hooks")
        if not os.path.isdir(theirs):
            self.skipTest("no ~/Developer/safecall on this computer")

        def lines(path):
            with open(path, "rb") as fh:
                return [line.rstrip() for line in fh.read().decode("utf-8").splitlines()]
        for name in ("python.sh", "python.ps1"):
            self.assertEqual(lines(os.path.join(theirs, name)), lines(os.path.join(ROOT, "hooks", name)), name)

    @unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7 is not installed here")
    @has_hooks
    def test_in_powershell_the_second_line_finds_python_and_passes_stdin_and_exit_code(self):
        command = hook_commands()[0]
        command = command.replace("${CLAUDE_PLUGIN_ROOT}", "${env:CLAUDE_PLUGIN_ROOT}")   # what Claude Code does
        # Only the second line: PowerShell 7 on Mac and Linux has an `exec` of its own (Switch-Process) and would
        # take the first; on Windows there is none, and the second line is what runs.
        command = command.split("\n")[1]
        fake_root = os.path.join(self.tmp, "root")
        os.makedirs(os.path.join(fake_root, "hooks"))
        shutil.copy(os.path.join(ROOT, "hooks", "python.ps1"), os.path.join(fake_root, "hooks"))
        script = command.split('"${env:CLAUDE_PLUGIN_ROOT}/', 2)[2].split('"')[0]
        os.makedirs(os.path.dirname(os.path.join(fake_root, script)), exist_ok=True)
        open(os.path.join(fake_root, script), "w").write(
            "import sys\nprint('got ' + sys.stdin.read().strip())\nsys.exit(2)\n")
        p = subprocess.run([shutil.which("pwsh"), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                            "-Command", command], input=WORD, capture_output=True, text=True, timeout=60,
                           env=dict(os.environ, CLAUDE_PLUGIN_ROOT=fake_root))
        self.assertEqual((p.returncode, p.stdout.strip()), (2, "got " + WORD), p.stderr)
        self.assertEqual(p.stderr, "")

    def test_a_skill_passes_the_script_relative_to_the_plugin_root(self):
        root = os.path.join(self.tmp, "plugin root")
        os.makedirs(os.path.join(root, "hooks"))
        os.makedirs(os.path.join(root, "skills", "x", "scripts"))
        shutil.copy(GUARD, os.path.join(root, "hooks"))
        open(os.path.join(root, "skills", "x", "scripts", "x.py"), "w").write(
            "import sys\nprint('args', sys.argv[1:], sys.stdin.read().strip())\nsys.exit(3)\n")
        elsewhere = os.path.join(self.tmp, "elsewhere")
        os.makedirs(os.path.join(elsewhere, "skills", "x", "scripts"))
        open(os.path.join(elsewhere, "skills", "x", "scripts", "x.py"), "w").write("print('the wrong script')\n")
        p = subprocess.run(["/bin/sh", "-c", 'sh "%s/hooks/python.sh" %s say skills/x/scripts/x.py list --folder "a b" <<\'EOF\'\n%s\nEOF'
                            % (root, PLUGIN, WORD)], cwd=elsewhere, capture_output=True, text=True, timeout=20,
                           env=dict(os.environ))
        self.assertEqual((p.returncode, p.stdout.strip()), (3, "args ['list', '--folder', 'a b'] " + WORD), p.stderr)

    def test_every_skill_runs_its_scripts_through_the_launcher(self):
        """No skill calls python3, python or py itself; every script it names exists; its allowed-tools let both the
        Bash form and the PowerShell form of that script run without a prompt (the rule must be quoted as the
        command is: Claude Code matches the command text, quotes included)."""
        self.assertTrue(SKILLS)
        named = 0
        for path in SKILLS:
            text = open(path, encoding="utf-8").read()
            name = os.path.relpath(path, ROOT)
            head = text.split("\n---\n", 1)[0]
            body = text.split("\n---\n", 1)[1]
            self.assertIsNone(re.search(r'(python3?|py -3)\s+"?\$\{CLAUDE_PLUGIN_ROOT\}', text), name)
            scripts = set(re.findall(re.escape(SH) + SCRIPT_PATH, body))
            for script in scripts:
                named += 1
                self.assertTrue(os.path.exists(os.path.join(ROOT, script)), "%s names %s" % (name, script))
                for rule in ("Bash(%s%s *)" % (SH, script), "PowerShell(%s%s *)" % (PS, script)):
                    self.assertIn(rule, head, "%s: allowed-tools lacks %s" % (name, rule))
            if scripts or "python.sh" in head:
                self.assertIn("## Running %s's scripts (Mac, Linux, Windows)" % PLUGIN, body, name)
                self.assertIn(PS.strip(), body.replace("\n", " "), name)
                self.assertIn('& "${CLAUDE_PLUGIN_ROOT}/hooks/python.ps1"', body, name)   # for a path with a space
        self.assertGreater(named, 0, "no skill names a script - the check above watched nothing")


if __name__ == "__main__":
    unittest.main()
