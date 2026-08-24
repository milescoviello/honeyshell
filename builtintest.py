#!/usr/bin/env python3
"""If `type` calls it a builtin, does it run?

An earlier sweep gave this shell bash's real builtin table, so
`command -v ulimit` and `type history` stopped denying builtins the shell
runs. That fixed one half of the question and opened the other: nine of
the names it now claimed had no implementation behind them, so the box
answered

    $ type fc
    fc is a shell builtin
    $ fc -l
    bash: fc: command not found

which is the same contradiction the table was meant to remove, pointing
the other way. bind, complete, compopt, dirs, fc, mapfile, popd, pushd and
readarray all did it.

They run now:

  - `fc -l` prints the same list `history` prints, from the same place, so
    the two spellings of "what have I typed" cannot disagree -- and both
    stay silent in a non-interactive shell, because bash keeps no history
    there.
  - pushd/popd/dirs keep a real directory stack, with bash's output and
    bash's two errors ("no other directory", "directory stack empty").
  - `mapfile -t arr < file` fills the array a script then indexes; it is
    how a loader slurps a target list.

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def sh(interactive=True, user="root"):
    s = fs.Shell(fs.VFS(), peer="203.0.113.77", user=user)
    s.exec_mode = not interactive
    return s


def run(s, cmd):
    out = s.run(cmd)
    err = "".join(s._err)
    s._err.clear()
    return (out + err), s.last_rc


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-52s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


# --- the claim and the behaviour have to match ------------------------------

def t_every_claimed_builtin_runs():
    s = sh()
    missing = []
    for b in sorted(s._BUILTINS):
        if b in ("exit", "logout", ".", "source"):
            continue          # would end or need an operand
        o, _ = run(s, b)
        if "command not found" in o:
            missing.append(b)
    eq("no builtin the shell claims is missing", missing, [])


def t_type_and_running_agree():
    s = sh()
    for b in ("fc", "dirs", "pushd", "popd", "mapfile", "readarray",
              "bind", "complete", "compopt", "ulimit", "history"):
        o, _ = run(s, "type %s" % b)
        check("type calls %s a builtin" % b, "shell builtin" in o, o[:50])
        o2, _ = run(s, "command -v %s" % b)
        eq("command -v %s prints the name" % b, o2.strip(), b)
        o3, _ = run(s, b)
        check("...and running %s is not command not found" % b,
              "command not found" not in o3, o3[:60])


def t_compgen_lists_what_runs():
    s = sh()
    o, _ = run(s, "compgen -b")
    names = o.split()
    check("compgen -b is bash-sized", len(names) > 50, len(names))
    for b in ("fc", "mapfile", "pushd"):
        check("compgen lists %s" % b, b in names, names[:5])


# --- history and fc are one list --------------------------------------------

def t_fc_and_history_are_the_same_list():
    s = sh()
    run(s, "echo alpha")
    run(s, "echo beta")
    h, _ = run(s, "history")
    f, _ = run(s, "fc -l")
    hcmds = [l.strip().split("  ", 1)[-1] for l in h.splitlines()]
    fcmds = [l.split("\t", 1)[-1] for l in f.splitlines()]
    check("history has the session's commands",
          "echo alpha" in hcmds and "echo beta" in hcmds, hcmds[-4:])
    for c in ("echo alpha", "echo beta"):
        check("fc -l has %s too" % c, c in fcmds, fcmds[-4:])


def t_neither_speaks_in_a_non_interactive_shell():
    """bash keeps no history without a terminal."""
    s = sh(interactive=False)
    o, _ = run(s, "echo one\necho two\nhistory")
    eq("history prints nothing", o.strip(), "one\ntwo")
    o2, _ = run(s, "fc -l")
    eq("and neither does fc", o2.strip(), "")


def t_clearing_history_clears_both():
    s = sh()
    run(s, "echo before")
    run(s, "history -c")
    o, _ = run(s, "history")
    check("the cleared list holds only what came after",
          "echo before" not in o, o[:80])
    o2, _ = run(s, "fc -l")
    check("fc agrees it is gone", "echo before" not in o2, o2[:80])


# --- the directory stack ----------------------------------------------------

def t_pushd_and_popd_move_and_remember():
    s = sh()
    o, rc = run(s, "pushd /etc")
    eq("rc", rc, 0)
    eq("pushd prints the stack", o.strip(), "/etc /root")
    o2, _ = run(s, "pwd")
    eq("and it moved", o2.strip(), "/etc")
    o3, _ = run(s, "dirs -v")
    eq("-v numbers the entries", o3.split(), ["0", "/etc", "1", "/root"])
    o4, rc4 = run(s, "popd")
    eq("popd rc", rc4, 0)
    eq("popd prints what is left", o4.strip(), "/root")
    o5, _ = run(s, "pwd")
    eq("and moved back", o5.strip(), "/root")


def t_the_stack_errors_are_bashs():
    s = sh()
    o, rc = run(s, "popd")
    eq("popping an empty stack is rc 1", rc, 1)
    check("with bash's wording", "directory stack empty" in o, o[:60])
    o2, rc2 = run(s, "pushd /nosuchdir")
    eq("pushing a missing directory is rc 1", rc2, 1)
    check("named", "/nosuchdir: No such file or directory" in o2, o2[:70])
    o3, _ = run(s, "pwd")
    eq("and nothing moved", o3.strip(), "/root")


def t_dirs_alone_is_the_current_directory():
    s = sh()
    o, _ = run(s, "dirs")
    eq("just here", o.strip(), "/root")
    run(s, "cd /tmp")
    o2, _ = run(s, "dirs")
    eq("which follows cd", o2.strip(), "/tmp")


# --- mapfile ----------------------------------------------------------------

def t_mapfile_fills_an_array():
    s = sh()
    run(s, "printf 'one\\ntwo\\nthree\\n' > /tmp/list")
    o, rc = run(s, "mapfile -t arr < /tmp/list; echo ${arr[1]}")
    eq("rc", rc, 0)
    eq("the second line is the second element", o.strip(), "two")
    o2, _ = run(s, "mapfile -t arr < /tmp/list; echo ${#arr[@]}")
    eq("and the count is right", o2.strip(), "3")
    o3, _ = run(s, "readarray -t a2 < /tmp/list; echo ${a2[2]}")
    eq("readarray is the same builtin", o3.strip(), "three")


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("t_")]


def main():
    for t in TESTS:
        try:
            t()
        except Exception as exc:                              # noqa: BLE001
            check(t.__name__, False, "crashed: %r" % (exc,))
    print("passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL[:10]))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
