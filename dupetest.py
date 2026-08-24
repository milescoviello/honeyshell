#!/usr/bin/env python3
"""No definition may silently shadow another.

Four sweeps in a row turned up the same bug by accident, each time while
looking for something else:

    sweep 87  _size_suffix defined twice, the two disagreeing about
              whether MB is 1024^2 or 1000^2
    sweep 88  cmd_nohup defined twice, the survivor being the one that
              never wrote nohup.out
    sweep 92  `ip rule` unreachable because the route branch tested
              startswith("r") first
    sweep 100 cmd_egrep = cmd_grep at the end of the class, shadowing a
              correct cmd_egrep earlier and dropping the -E

Python raises nothing for any of this. The later definition wins, the
earlier one reads as live code, and the two can disagree for months. So
this suite stops looking for them one at a time: it walks the AST and
fails if any class member or module-level name is bound twice, and it
pins the behaviours that were being shadowed so a regression shows up as
a wrong answer and not just a wrong file.

The scan found twelve in fakeshell.py the first time it ran. Eleven were
dead copies -- including a _SIGNALS table with POLL at 29 where the guest
says IO, and `cmd_ash = cmd_dash` / `cmd_zsh = cmd_bash` giving the box
two shells it does not have.
"""
import ast
import collections
import glob
import io
import os
import re
import sys

FAILS, CHECKS = [], []

# Names that are deliberately bound more than once, with the reason.
ALLOWED = {
    # A forward declaration: KERNEL_VER cannot be built until BOOT_TS has
    # been loaded, and the first binding says so in its comment.
    ("fakeshell.py", "module", "KERNEL_VER"),
    # PACKAGES is rebound to a sorted copy of itself, which is a
    # transformation and not a second definition.
    ("fakeshell.py", "Shell", "PACKAGES"),
    # detect.py registers every check through a decorator and reuses the
    # name `_c` for each one; the decorator keeps the function, so the
    # rebinding is the pattern rather than a mistake.
    ("detect.py", "module", "_c"),
    # shelltest rebuilds KNOWN as a filtered copy of itself, and says so.
    ("shelltest.py", "module", "KNOWN"),
}


def check(label, got, want):
    CHECKS.append(label)
    if got != want:
        FAILS.append((label, got, want))


def suite_manifest():
    """SUITES.md must list every suite on disk, and nothing else -- and each
    line must still describe the file it names.

    I overwrote two existing suites in three sweeps -- timertest.py in
    93e76fa and alttest.py in 3dc2c2a -- by picking a filename that was
    already taken, and read past the diffstat both times. A suite is
    added by adding a line to SUITES.md, and a name already there is
    impossible to miss. This check is what keeps the manifest honest.

    It happened a third time on 2026-08-24: memtest.py, 338 lines about
    whether the emulated box agrees with itself about its own RAM,
    overwritten by a new suite about whether the honeypot process fits in
    the RAM it is given. The set-comparison above passed, because the name
    was already listed -- a name check cannot see an overwrite.

    So the description is checked too. Every suite's first docstring line
    is its manifest description, which 155 of 158 already satisfied when
    this was added; overwrite a suite and its docstring no longer matches
    the line that describes it.
    """
    import glob
    here = os.path.dirname(os.path.abspath(__file__))
    on_disk = set(os.path.basename(p) for p in
                  glob.glob(os.path.join(here, "*test*.py")))
    on_disk |= {"detect.py", "probesuite.py"}
    described = {}
    path = os.path.join(here, "SUITES.md")
    if not os.path.exists(path):
        return ["SUITES.md is missing"]
    for line in io.open(path, encoding="utf-8"):
        m = re.match(r"^- `([^`]+)`\s*--\s*(.*?)\s*$", line)
        if m:
            described[m.group(1)] = m.group(2)
        else:
            m = re.match(r"^- `([^`]+)`", line)
            if m:
                described[m.group(1)] = None
    listed = set(described)
    bad = []
    for f in sorted(on_disk - listed):
        bad.append("%s is on disk and not in SUITES.md" % f)
    for f in sorted(listed - on_disk):
        bad.append("%s is in SUITES.md and not on disk" % f)
    # The line has to still describe the file. A name check cannot see an
    # overwrite; a description check can, because replacing a suite replaces
    # its docstring.
    for f in sorted(on_disk & listed):
        want = described.get(f)
        if want is None:
            bad.append("%s has no description in SUITES.md" % f)
            continue
        try:
            doc = ast.get_docstring(
                ast.parse(io.open(os.path.join(here, f),
                                  encoding="utf-8").read()))
        except (SyntaxError, OSError) as exc:
            bad.append("%s could not be read: %s" % (f, exc))
            continue
        if not doc or not doc.strip():
            bad.append("%s has no docstring" % f)
            continue
        first = doc.strip().splitlines()[0].strip()
        if first != want:
            bad.append("%s: SUITES.md says %r, its docstring opens %r"
                       % (f, want[:60], first[:60]))
    return bad


def duplicates(path, is_suite=False):
    """(scope, name, [lines]) for every name bound twice in one scope."""
    tree = ast.parse(open(path, encoding="utf-8").read())
    scopes = [("module", tree.body)]
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            scopes.append((node.name, node.body))
    out = []
    for sname, body in scopes:
        seen = collections.defaultdict(list)
        for item in body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                seen[item.name].append(item.lineno)
            elif isinstance(item, ast.Assign):
                # A rebound module-level *variable* in a linear script is
                # ordinary; a rebound class member is a shadowed
                # definition. So assignments count inside a class body,
                # and at module level only in the implementation modules
                # -- the suites reuse names like `rec` between cases and
                # that is not the bug this is looking for.
                if sname == "module" and is_suite:
                    continue
                for t in item.targets:
                    if isinstance(t, ast.Name):
                        seen[t.id].append(item.lineno)
        for name, lines in sorted(seen.items()):
            if len(lines) > 1:
                out.append((sname, name, lines))
    return out


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    files = sorted(glob.glob(os.path.join(here, "*.py")))
    files += [os.path.join(here, "..", "watch", "intel.py")]

    scanned, offenders = 0, []
    for path in files:
        base = os.path.basename(path)
        if not os.path.exists(path):
            continue
        scanned += 1
        suite = "test" in base or base in ("detect.py", "probesuite.py")
        for scope, name, lines in duplicates(path, is_suite=suite):
            if (base, scope, name) in ALLOWED:
                continue
            offenders.append("%s: %s.%s at %s" % (base, scope, name, lines))
    check("every module was scanned", scanned > 100, True)
    check("nothing is defined twice", offenders, [])
    # A suite file overwritten by a new one with the same name is the same
    # class of loss as a definition shadowed by a later one -- the earlier
    # work is gone and nothing complains. SUITES.md is the list; this is
    # what keeps it level with the directory.
    check("SUITES.md and the directory agree", suite_manifest(), [])

    # -- and the behaviours the shadowed copies would have changed ----------
    sys.path.insert(0, here)
    import fakeshell as F

    v = F.VFS()
    s = F.Shell(v, peer="203.0.113.88")
    s.exec_mode = True

    # _SIGNALS: the losing copy had POLL at 29; `kill -l 29` on the guest
    # says IO, and the whole table has to line up with it.
    check("signal 29 is IO, as the guest reports",
          F.Shell._SIGNALS[28], "IO")
    check("kill -l agrees", "29) SIGIO" in s.run("kill -l"), True)
    check("the table is the full 31", len(F.Shell._SIGNALS), 31)
    check("...starting at HUP and ending at SYS",
          (F.Shell._SIGNALS[0], F.Shell._SIGNALS[-1]), ("HUP", "SYS"))

    # zsh and ash are not installed, and the losing copies aliased them to
    # working shells.
    for name in ("zsh", "ash"):
        s._err = []
        out, rc = s.dispatch(name, [], "")
        check("%s is absent" % name, rc, 127)
        check("...and says so", "command not found" in "".join(s._err), True)
        check("...and is not on PATH", s.run("command -v %s" % name), "")
    for name in ("bash", "sh", "dash"):
        check("%s is still here" % name,
              s.run("command -v %s" % name).strip() != "", True)

    # The stub lambdas that were shadowed by real implementations.
    check("unset really unsets",
          s.run("X=1; unset X; echo [$X]").strip(), "[]")
    check("set -- sets the parameters",
          s.run("set -- a b c; echo $2").strip(), "b")
    check("true and false keep their statuses",
          (s.dispatch("true", [], "")[1], s.dispatch("false", [], "")[1]),
          (0, 1))
    check("history is empty on a non-interactive shell",
          s.run("history"), "")
    check("nohup writes nohup.out",
          (s.run("cd /root && nohup echo hi"),
           s.run("cat /root/nohup.out")), ("", "hi\n"))
    check("logout is exit",
          s.dispatch("logout", [], "")[1], 0)
    check("local is local",
          s.run("f() { local t=inner; }; t=outer; f; echo $t").strip(),
          "outer")

    # egrep and fgrep, from sweep 100 -- the alias that started this.
    check("egrep is not literally cmd_grep",
          F.Shell.cmd_egrep is F.Shell.cmd_grep, False)
    check("fgrep is not either",
          F.Shell.cmd_fgrep is F.Shell.cmd_grep, False)
    v2 = F.VFS()
    s2 = F.Shell(v2, peer="203.0.113.88")
    s2.exec_mode = True
    s2.fs.write("/tmp/d.txt", b"root root\nro+t\n")
    check("egrep takes an extended regex",
          s2.run("egrep 'ro+t' /tmp/d.txt"), "root root\n")
    check("fgrep takes a fixed string",
          s2.run("fgrep 'ro+t' /tmp/d.txt"), "ro+t\n")

    # _size_suffix, from sweep 87 -- the losing copy said MB was 1024^2.
    check("MB is a million, not a mebibyte",
          F.Shell._size_suffix("1MB"), 1000000)
    check("...and M is a mebibyte", F.Shell._size_suffix("1M"), 1048576)

    # ip rule, from sweep 92 -- the branch that could not be reached.
    check("ip rule is not ip route",
          s.run("ip rule").splitlines()[0], "0:\tfrom all lookup local")
    check("...and ip route is still itself",
          s.run("ip route").splitlines()[0].startswith("default via"), True)

    for label, got, want in FAILS:
        print("FAIL %s\n  got  %r\n  want %r" % (label, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("dupetest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
