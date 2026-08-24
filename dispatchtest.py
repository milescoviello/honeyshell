#!/usr/bin/env python3
r"""How a loader picks its payload: case dispatch and =~ tests.

Thirty-ninth coherence sweep. Every multi-arch dropper starts the same
way -- ask uname what the machine is, then branch:

    case $(uname -m) in
      x86_64|amd64) A=amd64 ;;
      aarch64|arm64) A=arm64 ;;
      armv7*) A=arm7 ;;
      *) A=unknown ;;
    esac

The loader at 203.0.113.25 fetched amd64, kal64, i686 and a generic
build on 2026-08-22, so getting the branch right decides which payload
we are shown.

The common forms were already sound: alternation with |, globs, ?, [3-6]
ranges, quoted patterns, command substitution as the subject, and the
whole `uname -m` dispatch above. Three were not:

  * `;;&` -- carry on testing the patterns below -- was split as ";;"
    followed by a stray "&", so only the first arm ran.
  * `;&` -- fall through to the next body without testing it -- was not
    recognised at all, which left the next arm's *pattern* to be run as a
    command: `case x in x) echo one;& y) echo two;; esac` printed one and
    then "bash: y): command not found" with rc 127. A loader using ;& got
    a syntax error from a shell that should have fallen through. split_top
    is not longest-match, which is why asking it for ";;" could never see
    ";;&"; the arms are split by a dedicated scanner now.
  * BASH_REMATCH was never set. The match half of `[[ $a =~ re ]]` worked
    and the capture half did not, so ${BASH_REMATCH[1]} came back empty
    from a comparison that had just succeeded -- and that array is how a
    script reads a version or an arch out of the string it just tested.

Reference measured on the guest, as root:

    case x in x) echo one;;& x) echo two;; esac        one two
    case x in x) echo one;;& y) echo two;; esac        one
    case x in x) echo one;&  y) echo two;; esac        one two
    case x in x) echo one;&  y) echo two;; z) ...      one two
    a=v1.2.3; [[ $a =~ v([0-9]+)\.([0-9]+) ]]          BASH_REMATCH 1,2 -> 1-2
    a=v1.2.3; [[ $a =~ v([0-9]+) ]]                    BASH_REMATCH[0] -> v1
    a=zz;     [[ $a =~ v([0-9]+) ]]                    rc 1, array empty

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def run(script):
    s = fs.Shell(fs.VFS(), peer="203.0.113.77")
    s.exec_mode = True
    out = s.run(script)
    err = "".join(s._err)
    s._err.clear()
    return (out + err), s.last_rc


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-46s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


def case(script, want, rc=0):
    out, got_rc = run(script)
    eq("out: %s" % script[:44], out.split(), want)
    eq("rc:  %s" % script[:44], got_rc, rc)


# -- the dispatch a loader actually writes -------------------------------

ARCH = ("case $(uname -m) in x86_64|amd64) echo AMD64;; "
        "aarch64|arm64) echo ARM64;; armv7*) echo ARM7;; "
        "i?86) echo X86;; *) echo OTHER;; esac")


def t_arch_dispatch():
    case(ARCH, ["AMD64"])


def t_pattern_forms():
    case("a=armv7l; case $a in armv7*) echo ARM7;; *) echo no;; esac",
         ["ARM7"])
    case("a=i686; case $a in i?86) echo X86;; *) echo no;; esac", ["X86"])
    case("a=i686; case $a in i[3-6]86) echo X86;; *) echo no;; esac",
         ["X86"])
    case("a=arm64; case $a in aarch64|arm64) echo ARM64;; *) echo no;; esac",
         ["ARM64"])
    case('a="*"; case $a in "*") echo literal;; *) echo glob;; esac',
         ["literal"])


def t_no_match_is_success():
    case("a=zz; case $a in x) echo one;; esac; echo rc=$?", ["rc=0"])


def t_substitution_inside_an_arm():
    case('a=x; case $a in x) echo "$(echo sub)";; esac', ["sub"])
    case('a=x; case $a in x) echo "(paren)";; esac', ["(paren)"])


# -- the three terminators -----------------------------------------------

def t_double_semicolon_stops():
    case("a=x; case $a in x) echo one;; x) echo two;; esac", ["one"])


def t_semicolon_amp_amp_tests_the_next_pattern():
    case("a=x; case $a in x) echo one;;& x) echo two;; esac", ["one", "two"])
    case("a=x; case $a in x) echo one;;& y) echo two;; esac", ["one"])
    case("a=x; case $a in x) echo one;;& x) echo two;;& x) echo three;; esac",
         ["one", "two", "three"])


def t_semicolon_amp_falls_through():
    case("a=x; case $a in x) echo one;& y) echo two;; esac", ["one", "two"])
    case("a=x; case $a in x) echo one;& y) echo two;; z) echo three;; esac",
         ["one", "two"])


def t_no_stray_command_not_found():
    """The ;& bug ran the next arm's pattern as a command."""
    out, rc = run("a=x; case $a in x) echo one;& y) echo two;; esac")
    check("no bogus command not found", "command not found" not in out, out)
    eq("rc 0", rc, 0)


def t_terminators_mixed():
    case("a=x; case $a in x) echo one;;& y) echo two;& z) echo three;; esac",
         ["one"])


# -- =~ and its captures -------------------------------------------------

def t_regex_match_still_works():
    case("a=x86_64; if [[ $a =~ ^x86 ]]; then echo yes; else echo no; fi",
         ["yes"])
    case("a=arm; if [[ $a =~ ^x86 ]]; then echo yes; else echo no; fi",
         ["no"])


def t_bash_rematch_groups():
    case('a=v1.2.3; [[ $a =~ v([0-9]+)\\.([0-9]+) ]]; '
         'echo "${BASH_REMATCH[1]}-${BASH_REMATCH[2]}"', ["1-2"])


def t_bash_rematch_zero_is_the_whole_match():
    case('a=v1.2.3; [[ $a =~ v([0-9]+) ]]; echo "${BASH_REMATCH[0]}"',
         ["v1"])


def t_bash_rematch_is_cleared_on_failure():
    case('a=zz; [[ $a =~ v([0-9]+) ]]; echo "rc=$? [${BASH_REMATCH[1]}]"',
         ["rc=1", "[]"])


def t_rematch_survives_to_the_next_command():
    """It is read on the line after the test, not in it."""
    case('a=SRBMiner-Multi-3-4-1-Linux; '
         '[[ $a =~ ([0-9]+)-([0-9]+)-([0-9]+) ]]; '
         'echo "v${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.${BASH_REMATCH[3]}"',
         ["v3.4.1"])


def t_glob_compare_in_double_brackets():
    case("a=armv7l; if [[ $a == armv7* ]]; then echo yes; else echo no; fi",
         ["yes"])
    case("a=x; if [[ $a != y ]]; then echo yes; fi", ["yes"])


TESTS = [t_arch_dispatch, t_pattern_forms, t_no_match_is_success,
         t_substitution_inside_an_arm, t_double_semicolon_stops,
         t_semicolon_amp_amp_tests_the_next_pattern,
         t_semicolon_amp_falls_through, t_no_stray_command_not_found,
         t_terminators_mixed, t_regex_match_still_works,
         t_bash_rematch_groups, t_bash_rematch_zero_is_the_whole_match,
         t_bash_rematch_is_cleared_on_failure,
         t_rematch_survives_to_the_next_command,
         t_glob_compare_in_double_brackets]


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
