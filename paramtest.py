#!/usr/bin/env python3
"""Parameter expansion, and what happens when one of them fails.

Thirty-second coherence sweep. The axis is ${...} expansion, chosen
because installer scripts are built out of it -- the SRBMiner one uses
arrays, ${#}, $( ) and $(( )) in its first twenty lines -- and because it
has a natural cross-command check: ${v##*/} has to agree with basename,
${v%/*} with dirname, and ${#v} with wc -c.

Nearly all of it was already right: #, ##, %, %%, /, //, :off, :off:len,
:-, :=, :+, ^, ^^, ,, ,,, indirect ${!x}, ${#arr[@]}, ${arr[i]} and
${arr[@]:i:n} all matched the guest. Two did not, and the first is the
worst kind:

  * `${VAR:?message}` set an _exiting flag that nothing ever cleared, so
    it outlived the command that raised it. Inside one script it correctly
    aborts, which is what a non-interactive bash does. But every *later*
    command in the same session then returned empty with rc 1 -- echo, id,
    uname, all of it. One unset variable in a staging script and the box
    went silent for the rest of the session: a total capture loss, and
    nothing a real shell does. An interactive bash does not even exit on
    ${x:?}. Session teardown never read the flag -- the interactive loop
    matches the literal string "exit" -- so it is now cleared at the top
    of each outermost run.
  * `${v:(-5)}` expanded to nothing. bash makes you disambiguate a
    negative offset from :- by writing either `${v: -5}` or `${v:(-5)}`;
    the space form was handled and the parenthesised one fell through
    every branch.

Reference measured on the guest, as root, with v=/opt/srb/kaudit.gz:

    ${v:(-5)}   it.gz          ${v: -2}    gz
    ${v:5}      srb/kaudit.gz  ${v:5:3}    srb
    ${v:(-6):3} dit            ${#v}       18
    ${v^^}      /OPT/SRB/KAUDIT.GZ

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []
V = "/opt/srb/kaudit.gz"


def sh():
    s = fs.Shell(fs.VFS(), peer="203.0.113.77")
    s.exec_mode = True
    s.run("v=%s; empty=; x=v; V=ABC; arr=(one two three); unset gone" % V)
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
        print("  FAIL %-46s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


# -- the forms, against figures measured on the guest --------------------

FORMS = [
    ("${v##*/}",      "kaudit.gz"),
    ("${v#*/}",       "opt/srb/kaudit.gz"),
    ("${v%/*}",       "/opt/srb"),
    ("${v%%.*}",      "/opt/srb/kaudit"),
    ("${v%.*}",       "/opt/srb/kaudit"),
    ("${#v}",         "18"),
    ("${v//a/X}",     "/opt/srb/kXudit.gz"),
    ("${v/a/X}",      "/opt/srb/kXudit.gz"),
    ("${v:5}",        "srb/kaudit.gz"),
    ("${v:5:3}",      "srb"),
    ("${v: -2}",      "gz"),
    ("${v:(-5)}",     "it.gz"),
    ("${v:(-6):3}",   "dit"),
    ("${gone:-d}",    "d"),
    ("${empty:-d}",   "d"),
    ("${empty-d}",    ""),
    ("${v:+alt}",     "alt"),
    ("${empty:+alt}", ""),
    ("${v^^}",        "/OPT/SRB/KAUDIT.GZ"),
    ("${V,,}",        "abc"),
    ("${V,}",         "aBC"),
    ("${v^}",         "/opt/srb/kaudit.gz"),
    ("${!x}",         V),
    ("${#arr[@]}",    "3"),
    ("${arr[1]}",     "two"),
    ("${arr[@]:1:2}", "two three"),
]


def t_every_form_matches_the_guest():
    s = sh()
    for form, want in FORMS:
        eq("%s quoted" % form, run(s, 'echo "%s"' % form)[0].strip(), want)


def t_quoted_and_unquoted_agree():
    """Two spellings of one expansion must not answer differently."""
    s = sh()
    for form, _want in FORMS:
        q = run(s, 'echo "%s"' % form)[0].strip()
        u = run(s, 'echo %s' % form)[0].strip()
        eq("%s same unquoted" % form, u, q)


def t_expansion_agrees_with_the_commands():
    s = sh()
    eq("${v##*/} == basename",
       run(s, 'echo "${v##*/}"')[0].strip(),
       run(s, 'basename "$v"')[0].strip())
    eq("${v%/*} == dirname",
       run(s, 'echo "${v%/*}"')[0].strip(),
       run(s, 'dirname "$v"')[0].strip())
    eq("${#v} == wc -c",
       run(s, 'echo "${#v}"')[0].strip(),
       run(s, 'printf %s "$v" | wc -c')[0].strip())


def t_assignment_forms_take_effect():
    s = sh()
    eq("${gone:=set} returns it",
       run(s, 'echo "${gone:=set}"')[0].strip(), "set")
    eq("and it stuck", run(s, 'echo "$gone"')[0].strip(), "set")


# -- ${x:?} must not outlive its command ---------------------------------

def t_colon_question_aborts_only_its_own_script():
    s = sh()
    out, rc = run(s, 'echo ${missing:?boom}')
    check("it reports the message", "boom" in out, out)
    eq("and exits 1", rc, 1)
    for probe, want in (("echo alive", "alive"), ("id -u", "0"),
                        ("uname -s", "Linux")):
        got, grc = run(s, probe)
        eq("%s still answers afterwards" % probe, got.strip(), want)
        eq("%s exits 0 afterwards" % probe, grc, 0)


def t_colon_question_still_stops_the_current_script():
    """Inside one script it must abort, as a non-interactive bash does."""
    s = sh()
    out, rc = run(s, 'echo one\necho ${missing:?boom}\necho two')
    check("the line before it ran", out.startswith("one"), out)
    check("the message appeared", "boom" in out, out)
    check("the line after it did not run", "two" not in out, out)
    eq("rc is 1", rc, 1)


def t_exit_does_not_silence_the_session_either():
    s = sh()
    _o, rc = run(s, "exit 3")
    eq("exit carries its status", rc, 3)
    got, grc = run(s, "echo still-here")
    eq("the next command still runs", got.strip(), "still-here")
    eq("and exits 0", grc, 0)
    out, _ = run(s, "echo one; exit; echo two")
    check("exit still ends its own script",
          out.strip() == "one", out)


def t_an_ordinary_failure_never_silenced_anything():
    """Control: this always worked, and must keep working."""
    s = sh()
    eq("false exits 1", run(s, "false")[1], 1)
    eq("and the next command runs",
       run(s, "echo alive")[0].strip(), "alive")


TESTS = [t_every_form_matches_the_guest, t_quoted_and_unquoted_agree,
         t_expansion_agrees_with_the_commands,
         t_assignment_forms_take_effect,
         t_colon_question_aborts_only_its_own_script,
         t_colon_question_still_stops_the_current_script,
         t_exit_does_not_silence_the_session_either,
         t_an_ordinary_failure_never_silenced_anything]


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
