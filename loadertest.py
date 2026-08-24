#!/usr/bin/env python3
"""What a downloaded installer script actually meets on the way to running.

This axis came from mining the capture for shell *syntax* that had been
dispatched as commands -- `fi`, `done`, `)`, `for tool in ; do`. All of it
came from one session: 203.0.113.33 on 2026-08-22 fetched an SRBMiner
installer, stripped its CRLF with sed, and ran it under sudo. Chasing that
found three defects on the path a loader takes, none of which any suite had
asked about.

A here-string took the whole rest of the line as its data. `cmd <<< word`
feeds exactly one word to stdin and everything after it is still the
command's, so the installer's

    dpkg --set-selections <<< "$pkg hold" 2>/dev/null || ...

fed "procps hold 2>/dev/null" to stdin and left stderr un-redirected --
three times over, inside a loop. The search for `<<<` is quote-aware now
too, for the same reason: `echo "a <<< b"` is a string, not a here-string.

sudo did not understand `--`. It fell through to the command slot, so
`sudo -- bash x.sh` answered "sudo: --: command not found" -- and `--` is
what a script writer reaches for when the command might begin with a dash.
Fixing that exposed a second one beside it: options can consume every
argument and leave nothing to run, and bare `sudo` printed the usage line
with exit 1 while `sudo --` and `sudo -u deploy` printed nothing with exit
0. Three spellings of one situation, one of which was right. -k and -K are
genuinely complete alone and still are.

dash has no arrays and we accepted them, so a script full of bash arrays ran
cleanly under `sh payload.sh` and did on a real box exactly nothing -- the
emulator being more capable than the shell it claims to be. Measured:
`sh s.sh` gives `s.sh: 2: Syntax error: "(" unexpected` and exit 2, naming
the script as invoked and the physical line. Getting that line number right
meant blanking the shebang rather than dropping it, which had been shifting
every error line in every script by one.

Not reproduced, and recorded here so the next sweep does not re-chase it:
the stray `fi`/`done`/`)` themselves. The line splitter joins that script
correctly into 51 logical lines with no bare keywords, on the build running
that day as well as on this one, and no reconstruction of its shapes --
multi-line arrays, nested loops, here-strings with backslash continuations
-- reproduces the leak on either build. Something between 08-22 and now
fixed it. The payload was never executed to find out.

Run from ~/opsec/honeypot:  python3 -W ignore loadertest.py
"""
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

# ---- here-strings, run as plain commands -----------------------------------
HERESTRING = [
    'cat <<< "hello"',
    'cat <<<plain',
    "cat <<< 'sq $x'",
    'x=p; cat <<< "$x hold" 2>/dev/null; echo rc=$?',
    'x=p; cat <<< "$x hold" 2>&1; echo rc=$?',
    'cat <<< word extra 2>/dev/null',
    'echo "a <<< b"',
    "echo 'a <<< b'",
    'x=q; cat <<< "$x hold" | tr a-z A-Z',
    'cat <<< "two words" > /tmp/o; cat /tmp/o',
    'cat <<< "$(echo sub)" 2>/dev/null',
    'for p in one two; do cat <<< "$p hold" 2>/dev/null || echo alt; done',
    'wc -w <<< "a b c" 2>/dev/null',
    'grep -c . <<< "x" 2>/dev/null',
]

# ---- sudo's own option parsing ---------------------------------------------
SUDO = [
    "sudo -- id -u; echo rc=$?",
    "sudo -- whoami",
    "sudo id -u",
    "sudo -u deploy -- whoami",
    "echo '123456' | sudo -S -- id -u",
    "sudo -k; echo rc=$?",
    "sudo -K; echo rc=$?",
    "sudo -k id -u",
]

# ---- and what each shell will accept from a file ---------------------------
SH_SCRIPT = '#!/bin/sh\nA=(1 2)\necho after\n'
BASH_SCRIPT = '#!/bin/bash\nA=(1 2)\necho "after ${A[1]}"\n'
LINENO_SCRIPT = '#!/bin/sh\necho one\necho two\nA=(1 2)\n'
SCRIPTS = [
    ("sh s.sh", SH_SCRIPT), ("./s.sh", SH_SCRIPT), ("bash s.sh", SH_SCRIPT),
    ("bash s.sh", BASH_SCRIPT), ("./s.sh", BASH_SCRIPT),
    ("sh s.sh", BASH_SCRIPT),
    ("sh s.sh", LINENO_SCRIPT), ("./s.sh", LINENO_SCRIPT),
]

# The shapes the installer used, rebuilt from scratch rather than replayed.
BLOCKS = {
    "multiline_array": 'TOOLS=(\n  "a" "b"\n  "c" "d"\n)\n'
                       'echo "n=${#TOOLS[@]}"\n'
                       'for t in "${TOOLS[@]}"; do echo "t=$t"; done\n',
    "for_with_herestring": 'for p in one two; do\n'
                           '  cat <<< "$p hold" 2>/dev/null || \\\n'
                           '  echo "alt $p" 2>/dev/null || true\n'
                           'done\necho AFTER\n',
    "if_block": 'if [ ! -d "/nope" ]; then\n  echo missing\nelse\n'
                '  echo present\nfi\n',
    "while_block": 'n=1\nwhile [ $n -le 3 ]; do\n  echo "n=$n"\n'
                   '  n=$((n+1))\ndone\n',
    "nested": 'n=1\nwhile [ $n -le 2 ]; do\n  if [ $n -eq 1 ]; then\n'
              '    echo first\n  fi\n  n=$((n+1))\ndone\n',
    "case_block": 'x=b\ncase "$x" in\n  a) echo is-a ;;\n  b) echo is-b ;;\n'
                  '  *) echo other ;;\nesac\n',
    "func_block": 'greet() {\n  echo "hello $1"\n}\ngreet world\n',
}


def real_cmd(cmd):
    tmp = tempfile.mkdtemp()
    r = subprocess.run(["bash", "--noprofile", "--norc", "-c",
                        "export LC_ALL=C; " + cmd],
                       capture_output=True, text=True, timeout=20, cwd=tmp)
    return r.stdout, r.stderr


def ours_cmd(cmd):
    sh = fs.Shell(fs.VFS())
    sh.exec_mode = True
    sh.run("rm -rf /w; mkdir -p /w")
    sh.cwd = "/w"
    del sh._err[:]
    return sh.run(cmd), "".join(sh._err)


def real_script(runner, body):
    tmp = tempfile.mkdtemp()
    p = os.path.join(tmp, "s.sh")
    open(p, "w").write(body)
    os.chmod(p, 0o755)
    r = subprocess.run(["bash", "--noprofile", "--norc", "-c",
                        "export LC_ALL=C; " + runner],
                       capture_output=True, text=True, timeout=20, cwd=tmp)
    return r.stdout, r.stderr


def ours_script(runner, body):
    sh = fs.Shell(fs.VFS())
    sh.exec_mode = True
    sh.run("rm -rf /w; mkdir -p /w")
    sh.cwd = "/w"
    sh.fs.write("/w/s.sh", body.encode(), mode=0o755)
    del sh._err[:]
    return sh.run(runner), "".join(sh._err)


def main():
    verbose = "-v" in sys.argv
    ok = bad = 0

    def compare(label, real, ours):
        nonlocal ok, bad
        if real == ours:
            ok += 1
            if verbose:
                print("  ok      %s" % label)
            return
        bad += 1
        print("  DIFFER  %s" % label)
        if real[0] != ours[0]:
            print("     real out: %r" % real[0][:200])
            print("     ours out: %r" % ours[0][:200])
        if real[1] != ours[1]:
            print("     real err: %r" % real[1][:200])
            print("     ours err: %r" % ours[1][:200])

    for cmd in HERESTRING:
        compare("$ " + cmd, real_cmd(cmd), ours_cmd(cmd))

    # sudo cannot be diffed against this host -- the build user's real sudo
    # rejects the persona's password -- so these are pinned to what the guest
    # does, measured there.
    expect = {
        "sudo -- id -u; echo rc=$?": ("0\nrc=0\n", ""),
        "sudo -- whoami": ("root\n", ""),
        "sudo id -u": ("0\n", ""),
        "sudo -u deploy -- whoami": ("deploy\n", ""),
        "echo '123456' | sudo -S -- id -u": ("0\n", ""),
        "sudo -k; echo rc=$?": ("rc=0\n", ""),
        "sudo -K; echo rc=$?": ("rc=0\n", ""),
        "sudo -k id -u": ("0\n", ""),
    }
    for cmd in SUDO:
        compare("$ " + cmd, expect[cmd], ours_cmd(cmd))
    for cmd, want in (("sudo", ("usage: sudo -h | -K | -k | -V\n", "")),
                      ("sudo --", ("usage: sudo -h | -K | -k | -V\n", "")),
                      ("sudo -u deploy",
                       ("usage: sudo -h | -K | -k | -V\n", "")),
                      ("sudo -S", ("usage: sudo -h | -K | -k | -V\n", ""))):
        compare("$ %s  (nothing to run)" % cmd, want, ours_cmd(cmd))

    for runner, body in SCRIPTS:
        tag = "sh" if body.startswith("#!/bin/sh") else "bash"
        compare("%s  (%s script)" % (runner, tag),
                real_script(runner, body), ours_script(runner, body))

    for name, body in sorted(BLOCKS.items()):
        for runner in ("bash s.sh", "./s.sh",
                       "echo '123456' | sudo -S bash s.sh"):
            full = "#!/bin/bash\n" + body
            if runner.startswith("echo"):
                # sudo is not comparable against this host; assert instead
                # that running it under sudo gives what running it plainly
                # gives, which is the property that matters.
                compare("%s via sudo matches plain" % name,
                        ours_script("bash s.sh", full),
                        ours_script(runner, full))
                continue
            compare("%s via %s" % (name, runner),
                    real_script(runner, full), ours_script(runner, full))

    print("\nloadertest: passed %d, failed %d" % (ok, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
