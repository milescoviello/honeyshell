"""The README's examples said things the code does not print.

The public README opens with Python that a reader is invited to paste, and
under each print() a comment giving the output. Nothing ever ran them. When
they were finally run on 2026-09-22, three of eight were false:

    df -h / | tail -1
        claimed  /dev/sda1        63G  4.1G   56G   7% /
        printed  /dev/sda1       1.8T  384G  1.3T  23% /

a figure from an earlier persona that had outlived it; an example wrapped
across two comment lines that silently dropped a field; and a "command not
found" shown as output when it goes to stderr, so print() of it prints an
empty line. A README is the one document every reader trusts first, and an
example that does not reproduce is worse than no example, because it tells
the reader their copy is broken.

So the examples are run. Every ```python block is executed in order in one
fresh Shell, exactly as a reader would paste it, and every print(sh.run(...))
must produce the comment lines beneath it, whole -- not a prefix. A claim
line may end in `<- note`, which is commentary and is not compared.

Finds the README next to itself in the public tree, and under
public-assets/ in the private one, where the public README is kept.

Usage:  python3 readmetest.py
"""

import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import fakeshell                                                # noqa: E402

CHECKS, FAILS = [], []


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want, "\n  -- " + note if note else ""))


def readme_path():
    for cand in (os.path.join(HERE, "public-assets", "README.md"),
                 os.path.join(HERE, "README.md")):
        try:
            head = io.open(cand, encoding="utf-8").read(200)
        except OSError:
            continue
        if head.startswith("# honeyshell"):
            return cand
    return None


def text(out):
    return (out[0] if isinstance(out, tuple) else out) or ""


path = readme_path()
check("the public README is where it should be", path is not None, True)
src = io.open(path, encoding="utf-8").read() if path else ""
blocks = re.findall(r"```python\n(.*?)```", src, re.S)
check("it has examples to run", len(blocks) >= 1, True)

sh = fakeshell.Shell()
lines = "\n".join(blocks).split("\n")
examples = 0
i = 0
while i < len(lines):
    ln = lines[i]
    m = re.match(r'print\(sh\.run\("(.*)"\)\)\s*$', ln)
    if m:
        cmd = m.group(1).replace('\\"', '"')
        claimed = []
        j = i + 1
        while j < len(lines) and lines[j].startswith("# "):
            claimed.append(lines[j][2:])
            j += 1
        want = [re.sub(r"\s+<- .*$", "", c).rstrip() for c in claimed]
        got = [g.rstrip() for g in text(sh.run(cmd)).rstrip("\n").split("\n")]
        examples += 1
        check("README example: %s" % cmd, got, want,
              "the comment under this print() is what a reader is told to "
              "expect")
        i = j
        continue
    m = re.match(r'sh\.run\("(.*)"\)\s*$', ln)
    if m:
        sh.run(m.group(1).replace('\\"', '"'))
    i += 1
check("every print() in the README was checked", examples >= 5, True,
      "found %d" % examples)

for f in FAILS:
    print(" ", f)
print("   readme: %d checks, %d differ" % (len(CHECKS), len(FAILS)))
sys.exit(1 if FAILS else 0)
