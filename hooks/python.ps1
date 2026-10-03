# Step 0 guard, PowerShell twin of hooks/python.sh: run a hook script with a REAL Python 3, or do
# nothing at all.
#
#   <plugin> <say|quiet> <script.py> [args...]
#
# Hooks load it as a script block and pass the script's full path. Skills run it as a file through
# Claude Code's PowerShell tool (Windows without Git Bash) - & "<plugin root>/hooks/python.ps1"
# <plugin> say scripts/x.py ... - with the script relative to the plugin root, and may pipe text in
# (@'...'@ | & ...), which then goes to the script's stdin as UTF-8.
#
# Why (02.10.2026). On Windows without Git Bash, Claude Code runs a hook command in PowerShell
# (`pwsh` or `powershell` -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command <command>),
# where `sh` does not exist. Every command in hooks.json is therefore two lines: the first,
# `exec sh .../python.sh ...`, is what sh and Git Bash run (exec replaces the shell, so they never
# read the second line); in PowerShell `exec` is no command, so it goes on to the second line, which
# loads this file as a script block - a script block is never stopped by the execution policy. That
# line starts with `trap { continue }`: a trap covers its whole scope, the line before it too, so
# PowerShell never prints "exec is not recognized" in front of what a guard has to say.
#
# Same rules as python.sh. python.org's Python is called `python` or `py` on Windows; `python` and
# `python3` may be the Microsoft Store stub, which answers `-c` with exit 9009 and never opens the
# Store, so a candidate counts only after `-c` proves it is Python 3.8+. Nothing found: `say` prints
# one line for Claude, `quiet` prints nothing; both exit 0. Stdin is left alone for the real script.
# The real script is started as a plain process on PowerShell's own stdin and stdout, so its UTF-8
# output reaches Claude Code untouched, and PYTHONUTF8 makes Python read the hook's JSON as UTF-8
# (not in the ANSI code page).
$plugin = $args[0]
$mode = $args[1]
$script = $args[2]
$rest = @($args | Select-Object -Skip 3)
$piped = @($input)
if ($script -and -not [System.IO.Path]::IsPathRooted($script) -and $PSScriptRoot) {
  $script = Join-Path (Split-Path -Parent $PSScriptRoot) $script
}

$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'

function Quote-Argument([string]$a) {   # one argument of a Windows command line, as a C program reads it back
  if ($a -ne '' -and $a -notmatch '[\s"]') { return $a }
  $out = '"'; $slashes = 0
  foreach ($ch in $a.ToCharArray()) {
    if ($ch -eq [char]92) { $slashes++; continue }
    if ($ch -eq '"') { $out += ([string][char]92 * (2 * $slashes + 1)) + '"' }
    else { $out += ([string][char]92 * $slashes) + $ch }
    $slashes = 0
  }
  return $out + ([string][char]92 * (2 * $slashes)) + '"'
}

$check = 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)'
function Try-Python([string]$file, [string[]]$pre) {   # run the script with it and exit, if -c proves it is Python 3.8+
  if (-not $file) { return }
  try { & $file @pre -c $check 2>$null | Out-Null } catch { return }
  if ($LASTEXITCODE -ne 0) { return }
  # Not `& python ...`: PowerShell would read the script's output and write it again in its own encoding.
  # A process started this way gets PowerShell's own stdin, stdout and stderr, byte for byte.
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $file
  $psi.Arguments = (@($pre) + @($script) + @($rest) | ForEach-Object { Quote-Argument $_ }) -join ' '
  $psi.UseShellExecute = $false
  $psi.RedirectStandardInput = ($piped.Count -gt 0)
  $noBom = New-Object System.Text.UTF8Encoding $false
  $consoleIn = $null
  if ($piped.Count -gt 0) {
    # Windows PowerShell 5.1 (.NET Framework) opens the child's stdin in the console's input encoding and writes
    # its byte order mark first; PowerShell 7 lets us name the encoding. Either way: UTF-8, no BOM.
    if ($psi.PSObject.Properties['StandardInputEncoding']) { $psi.StandardInputEncoding = $noBom }
    else { try { $consoleIn = [Console]::InputEncoding; [Console]::InputEncoding = $noBom } catch { $consoleIn = $null } }
  }
  $proc = [System.Diagnostics.Process]::Start($psi)
  if ($consoleIn) { try { [Console]::InputEncoding = $consoleIn } catch { } }
  if ($piped.Count -gt 0) {   # text piped into this file: hand it to the script as UTF-8, then close stdin
    $bytes = $noBom.GetBytes((($piped | ForEach-Object { [string]$_ }) -join "`n") + "`n")
    $proc.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
    $proc.StandardInput.Close()
  }
  $proc.WaitForExit()
  exit $proc.ExitCode
}

# 1. The PATH this process got: python.org's `python`, the launcher `py -3`, then `python3`.
foreach ($candidate in @('python', 'py -3', 'python3')) {
  $words = $candidate.Split(' ')
  $exe = Get-Command $words[0] -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($exe) { Try-Python $exe.Source @($words | Select-Object -Skip 1) }
}

# 2. A Python installed after Claude Code started (02.10.2026). An installer writes the new PATH into the
# registry, but Claude Code - and every hook and shell it starts - keeps the PATH it was started with, so the
# Python of step 0 is not on it until Claude Code restarts. So look where python.org's installer (and winget,
# which runs it) puts Python, newest first: the launcher, the per-user folders, and the install paths every
# installer registers (PEP 514). The Store stub lives in WindowsApps, never in these places, and `-c` rules it
# out anyway.
function Version-Of([string]$name) {   # "Python312" / "3.12-32" -> 312, for newest-first order
  $d = ($name -replace '-.*$', '') -replace '[^0-9]', ''
  if ($d) { return [int]$d } else { return 0 }
}
$local = $env:LOCALAPPDATA
$launchers = @()
if ($local) { $launchers += Join-Path $local 'Programs\Python\Launcher\py.exe' }
if ($env:SystemRoot) { $launchers += Join-Path $env:SystemRoot 'py.exe' }
foreach ($l in $launchers) { if (Test-Path -LiteralPath $l -PathType Leaf) { Try-Python $l @('-3') } }
$found = @()
foreach ($base in @($(if ($local) { Join-Path $local 'Programs\Python' }), $env:ProgramFiles)) {
  if (-not $base -or -not (Test-Path -LiteralPath $base)) { continue }
  Get-ChildItem -LiteralPath $base -Directory -Filter 'Python3*' -ErrorAction SilentlyContinue |
    Sort-Object { Version-Of $_.Name } -Descending |
    ForEach-Object { $found += Join-Path $_.FullName 'python.exe' }
}
foreach ($key in @('HKCU:\Software\Python\PythonCore', 'HKLM:\Software\Python\PythonCore',
                   'HKLM:\Software\WOW6432Node\Python\PythonCore')) {
  Get-ChildItem -LiteralPath $key -ErrorAction SilentlyContinue |
    Where-Object { $_.PSChildName -like '3*' } |
    Sort-Object { Version-Of $_.PSChildName } -Descending |
    ForEach-Object {
      $ip = Get-ItemProperty -LiteralPath (Join-Path $_.PSPath 'InstallPath') -ErrorAction SilentlyContinue
      if ($ip -and $ip.ExecutablePath) { $found += [string]$ip.ExecutablePath }
      elseif ($ip -and $ip.'(default)') { $found += Join-Path ([string]$ip.'(default)') 'python.exe' }
    }
}
$tried = @{}
foreach ($f in $found) {
  if ($tried.ContainsKey($f)) { continue }
  $tried[$f] = $true
  if (Test-Path -LiteralPath $f -PathType Leaf) { Try-Python $f @() }
}

if ($mode -eq 'say') {
  Write-Output "$plugin is paused: it starts working the moment this computer has Python 3. Tell the person in one line and do step 0 first (in the Poly A1 folder it is the first step of START-HERE): Mac - xcode-select --install, then press Install in Apple's window and wait 5-10 minutes; Windows - winget install -e --id Python.Python.3.12 --scope user; Linux - sudo apt-get install -y python3. No restart of Claude Code is needed after that."
}
exit 0
