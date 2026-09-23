#!/usr/bin/env python3
"""Does the box draw the same process tree twice?

`pstree` drew a correct tree. `ps axjf`, `ps f`, `ps -eH` and `ps --forest`
drew a flat list. Anyone reading a process tree reaches for one of those
first, and the two answers did not match.

The cause was a stub. The flag was parsed, and then:

    indent = "" if not forest else ""

Both branches empty. The forest option had been wired up as far as a
boolean and no further, so every tree-shaped `ps` printed a list.

Three separate faults, all now fixed:

**`--forest` was not a recognised option at all.** It fell through to the
format parser, which read the tail of the flag as a field name, so
`ps --forest -e` printed a column headed **REST**. A column named after a
fragment of its own flag is not something a real ps has ever printed.

**`-H` and `H` had been folded together.** The option string was built with
`x.lstrip("-")`, which throws away the one character that distinguishes
them: in procps the dashed Unix option `-H` means *hierarchy* and the bare
BSD option `H` means *threads*. So `ps -ejH` -- the standard way to ask for
the tree -- returned one row per thread, 566 rows, and no tree.

**The two indent styles are not the same.** Measured on procps-ng:

    ps f / --forest    "00:00:00  \\_ tmux"      marker, 2 spaces per level
    ps -eH             "00:00:00   pool_wq"      indent only, no marker

## What was checked and left alone

`pstree` shows 17 lines for 489 processes and that is correct: with no
arguments it walks the tree from pid 1, and `kthreadd` is pid 2, a separate
root, so a real `pstree` on a box with 353 kernel threads does not show one
of them either -- verified on a live machine. It also collapses repeated
siblings, and ours already did: `nginx---2*[nginx]`, `4*[python3]`.

## Still outstanding, deliberately

The `j` column format is not implemented. `ps axjf` now draws the tree but
still prints the default `PID TTY TIME CMD` header where procps prints
`PPID PID PGID SID TTY TPGID STAT UID TIME COMMAND`. Doing it properly
means modelling process groups and session ids, which this box does not
carry yet, and inventing them per-row would create exactly the kind of
inconsistency these sweeps exist to remove. Written down rather than
guessed. `ps aux H` likewise still ignores the threads flag in the aux
format branch.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fakeshell

CHECKS, FAILS = [], []


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want,
                        ("\n  -- " + str(note)) if note else ""))


def shell():
    return fakeshell.Shell(vfs=fakeshell.VFS(), peer="198.51.100.13",
                           peer_port=40333)


def main():
    sh = shell()
    def run(c):
        return sh.run(c) or ""

    # -- the table the tree is built from --------------------------------
    rows = []
    for ln in run("ps -eo pid,ppid,comm --no-headers").splitlines():
        f = ln.split()
        if len(f) >= 3 and f[0].isdigit() and f[1].isdigit():
            rows.append((int(f[0]), int(f[1]), f[2]))
    pids = {r[0] for r in rows}
    check("the process table is populated", len(rows) > 400, True, len(rows))
    check("every PPID names a process that exists",
          [r for r in rows if r[1] not in pids and r[1] != 0], [])
    parent = {r[0]: r[1] for r in rows}

    def roots_to(pid):
        seen = set()
        while pid in parent and pid not in seen:
            seen.add(pid)
            pid = parent[pid]
            if pid in (0, 1, 2):
                return pid
        return None

    check("every process descends from init or kthreadd",
          [r[0] for r in rows if roots_to(r[0]) is None], [])
    check("pid 1 is init and has no parent",
          [(r[1], r[2]) for r in rows if r[0] == 1], [(0, "systemd")])
    check("pid 2 is kthreadd and has no parent",
          [(r[1], r[2]) for r in rows if r[0] == 2], [(0, "kthreadd")])
    check("the kernel threads hang off kthreadd, not init",
          len([r for r in rows if r[1] == 2]) > 400, True,
          len([r for r in rows if r[1] == 2]))

    # -- the forest forms ------------------------------------------------
    flat = run("ps -e").splitlines()
    for cmd in ("ps axjf", "ps --forest -e", "ps -e --forest"):
        out = run(cmd).splitlines()
        marks = sum(1 for l in out if "\\_" in l)
        check("%s draws the tree" % cmd, marks > 100, True,
              "%d rows carry a marker" % marks)
        check("%s prints every process, once" % cmd, len(out), len(flat))
        check("%s does not invent a column" % cmd,
              "REST" in (out[0] if out else ""), False,
              "--forest was read as a field name")

    # -- -H indents, and does not mark ------------------------------------
    for cmd in ("ps -eH", "ps -ejH"):
        out = run(cmd).splitlines()
        check("%s uses indentation, not a marker" % cmd,
              sum(1 for l in out if "\\_" in l), 0)
        check("%s is a process list, not a thread list" % cmd,
              len(out), len(flat),
              "dashed -H is hierarchy; bare H is threads")
        indented = [l for l in out[1:] if re.match(r"^\s*\d+ \S+\s+\S+\s{2,}\S", l)]
        check("%s indents the children" % cmd, len(indented) > 100, True,
              len(indented))

    # -- bare H and -L are still threads ----------------------------------
    check("-eL lists threads, so it is longer than the process list",
          len(run("ps -eL").splitlines()) > len(flat), True)

    # -- a child never precedes its parent --------------------------------
    order = {}
    seen_order = []
    for i, l in enumerate(run("ps axjf").splitlines()[1:]):
        m = re.match(r"\s*(\d+)\s", l)
        if m:
            order[int(m.group(1))] = i
            seen_order.append(int(m.group(1)))
    bad = [p for p in seen_order
           if parent.get(p) in order and order[parent[p]] > order[p]]
    check("in the forest, no child is printed before its parent", bad, [],
          bad[:6])

    # -- pstree, which was already right ----------------------------------
    pt = run("pstree")
    check("pstree roots at init", pt.strip().startswith("systemd"), True,
          pt[:40])
    check("pstree does not show kernel threads, as on a real box",
          "kthreadd" in pt, False,
          "pstree with no argument walks pid 1's tree only")
    check("pstree collapses repeated siblings",
          bool(re.search(r"\d+\*\[", pt)), True, pt[:200])

    print("%d/%d assertions pass" % (sum(CHECKS), len(CHECKS)))
    for f in FAILS:
        print(f)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
