#!/usr/bin/env python3
"""Where is this program? Do the five ways of asking agree?

Thirty-fourth coherence sweep. `command -v`, `type`, `which`, `hash -t`
and PATH lookup all answer one question, so they have to answer it the
same way. The axis picked itself: 203.0.113.33 opened its SRBMiner run
with `command -v apt-get` and `command -v curl || echo missing`, which is
how nearly every loader chooses its downloader. If that gate answers
wrongly the actor takes the wrong branch and we never see the payload
they would otherwise have fetched.

The plain forms were right -- command -v, type and which agreed on a real
binary and all failed together on a missing one. The flags were not
recognised at all, and an unrecognised flag was taken as a *name*:

  * `type -t curl` printed "curl is /usr/bin/curl" for the operand and
    then "bash: type: -t: not found" for the flag, on stderr, rc 1.
    `[ "$(type -t foo)" = function ]` -- the usual way to ask whether
    something is defined before calling it -- got a sentence and a
    failure instead of one word. bash prints file, builtin, keyword or
    function.
  * `type -P` the same. It should print the on-disk path and nothing
    else, and fail for a builtin.
  * `type -a` listed only the first hit, not every one on PATH.
  * `command -V` answered like -v with a bare path, so `command -V cd`
    said "cd" where bash says "cd is a shell builtin".
  * `hash -t ls` looked up a command called "-t".
  * `command -v` on a *function* answered nothing: functions and keywords
    fell through to `which`, which knows about neither. A script asking
    whether the helper it just defined exists was told it does not.
  * `type` on a function printed only the header line; bash follows it
    with the definition.

Reference measured on the guest, as root:

    type -t ls        file        rc=0    type -P ls   /usr/bin/ls  rc=0
    type -t cd        builtin     rc=0    type -P cd   (empty)      rc=1
    type -t if        keyword     rc=0    command -V cd  cd is a shell builtin
    type -t nosuch    (empty)     rc=1    command -v if  if
    hash ls; hash -t ls  /usr/bin/ls      command -V if  if is a shell keyword
    hash -t nosuch    bash: hash: nosuch: not found  rc=1
    type -a ls        ls is /usr/bin/ls / ls is /bin/ls

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def sh():
    s = fs.Shell(fs.VFS(), peer="203.0.113.77")
    s.exec_mode = True
    s.run("myfunc(){ echo hi; }")
    s._err.clear()
    return s


def run(s, cmd):
    out = s.run(cmd)
    err = "".join(s._err)
    s._err.clear()
    return (out + err), s.last_rc


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-48s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


def case(s, cmd, want_out, want_rc):
    out, rc = run(s, cmd)
    eq("out: %s" % cmd, out.strip(), want_out)
    eq("rc:  %s" % cmd, rc, want_rc)


# -- type -t: one word, machine readable ---------------------------------

def t_type_t():
    s = sh()
    case(s, "type -t ls", "file", 0)
    case(s, "type -t cd", "builtin", 0)
    case(s, "type -t if", "keyword", 0)
    case(s, "type -t while", "keyword", 0)
    case(s, "type -t myfunc", "function", 0)
    case(s, "type -t nosuchtool", "", 1)


def t_the_defined_check_a_script_actually_writes():
    s = sh()
    eq("[ $(type -t myfunc) = function ]",
       run(s, '[ "$(type -t myfunc)" = function ] && echo yes || echo no'
           )[0].strip(), "yes")
    eq("and no for something undefined",
       run(s, '[ "$(type -t nope)" = function ] && echo yes || echo no'
           )[0].strip(), "no")


# -- type -P / -a --------------------------------------------------------

def t_type_P_is_the_path_only():
    s = sh()
    case(s, "type -P ls", "/usr/bin/ls", 0)
    case(s, "type -P cd", "", 1)
    case(s, "type -P myfunc", "", 1)
    case(s, "type -P nosuchtool", "", 1)


def t_type_a_lists_every_hit():
    s = sh()
    out, rc = run(s, "type -a ls")
    lines = [l for l in out.strip().split("\n") if l]
    eq("rc 0", rc, 0)
    check("more than one location", len(lines) > 1, out)
    check("first is /usr/bin", lines[0] == "ls is /usr/bin/ls", out)
    check("all are ls", all(l.startswith("ls is /") for l in lines), out)


# -- command -v / -V -----------------------------------------------------

def t_command_v_names_bare_and_paths_full():
    s = sh()
    case(s, "command -v ls", "/usr/bin/ls", 0)
    case(s, "command -v cd", "cd", 0)
    case(s, "command -v if", "if", 0)
    case(s, "command -v myfunc", "myfunc", 0)
    case(s, "command -v nosuchtool", "", 1)


def t_command_V_is_the_sentence():
    s = sh()
    case(s, "command -V ls", "ls is /usr/bin/ls", 0)
    case(s, "command -V cd", "cd is a shell builtin", 0)
    case(s, "command -V if", "if is a shell keyword", 0)


# -- hash ----------------------------------------------------------------

def t_hash_t():
    s = sh()
    case(s, "hash ls; hash -t ls", "/usr/bin/ls", 0)
    out, rc = run(s, "hash -t nosuchtool")
    check("missing name reports", "hash: nosuchtool: not found" in out, out)
    eq("and fails", rc, 1)


# -- type on a function --------------------------------------------------

def t_type_shows_a_function_body():
    s = sh()
    out, rc = run(s, "type myfunc")
    eq("rc 0", rc, 0)
    eq("header then definition", out.strip().split("\n")[0],
       "myfunc is a function")
    check("the body is shown", "echo hi" in out, out)


# -- they must all agree -------------------------------------------------

PRESENT = ["ls", "curl", "wget", "sh", "chmod"]
ABSENT = ["nosuchtool", "definitelynot", "zzz9"]


def t_every_lookup_agrees_on_a_real_binary():
    s = sh()
    for nm in PRESENT:
        got = {
            "command -v": run(s, "command -v %s" % nm)[0].strip(),
            "which": run(s, "which %s" % nm)[0].strip(),
            "type -P": run(s, "type -P %s" % nm)[0].strip(),
            "hash -t": run(s, "hash -t %s" % nm)[0].strip(),
        }
        check("all four agree on %s" % nm, len(set(got.values())) == 1,
              repr(got))
        check("%s resolves under a bin dir" % nm,
              got["which"].startswith("/"), repr(got))
        eq("type -t says file for %s" % nm,
           run(s, "type -t %s" % nm)[0].strip(), "file")


def t_every_lookup_agrees_on_an_absent_one():
    s = sh()
    for nm in ABSENT:
        for probe in ("command -v", "which", "type -P", "type -t"):
            out, rc = run(s, "%s %s" % (probe, nm))
            eq("%s %s is empty" % (probe, nm), out.strip(), "")
            eq("%s %s fails" % (probe, nm), rc, 1)


def t_the_loader_gate():
    """`command -v curl || command -v wget` is how they pick a downloader."""
    s = sh()
    eq("curl branch taken",
       run(s, "command -v curl || echo missing")[0].strip(), "/usr/bin/curl")
    eq("missing branch taken",
       run(s, "command -v nosuchtool || echo missing")[0].strip(), "missing")
    eq("apt-get is found",
       run(s, "command -v apt-get")[0].strip(), "/usr/bin/apt-get")


TESTS = [t_type_t, t_the_defined_check_a_script_actually_writes,
         t_type_P_is_the_path_only, t_type_a_lists_every_hit,
         t_command_v_names_bare_and_paths_full, t_command_V_is_the_sentence,
         t_hash_t, t_type_shows_a_function_body,
         t_every_lookup_agrees_on_a_real_binary,
         t_every_lookup_agrees_on_an_absent_one, t_the_loader_gate]


def main():
    for t in TESTS:
        try:
            t()
        except Exception as exc:                              # noqa: BLE001
            check(t.__name__, False, "crashed: %r" % (exc,))
    print("passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL[:8]))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
