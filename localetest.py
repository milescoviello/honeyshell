#!/usr/bin/env python3
"""Does the box agree with itself about what locale it is running in?

`locale` read only $LANG. So `export LC_ALL=C; locale` went on reporting
C.UTF-8 in every category while `echo $LC_ALL` said C -- two answers to one
question. That is not a hypothetical: the recon payload this honeypot sees
most often opens with

    ( export LANG=C LC_ALL=C; echo '===SHELL_BEHAVIOR==='; ... )

precisely to pin the locale before it harvests error strings, because
message text changes with LC_MESSAGES. A box that ignores the pinning is
a box whose error strings cannot be trusted to match what the actor
expects.

Three things were wrong, all checked here against glibc on
debian:trixie-slim:

  - LC_ALL was ignored. Precedence is LC_ALL, then the category's own
    variable, then LANG.
  - Every category was printed quoted. glibc quotes a value it *derived*
    and leaves one set explicitly in the environment unquoted, which is
    how you tell `LC_TIME=C` from a LANG that happens to be C.
  - An uninstalled locale was accepted in silence. glibc names LC_CTYPE,
    LC_MESSAGES and LC_ALL on stderr and then prints the values anyway,
    exiting 0.

And `locale -a` listed C.utf8 on a box with no /usr/lib/locale at all --
the command named a locale the filesystem could not confirm.

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                        # noqa: E402

PASS, FAIL = [], []

CATEGORIES = ["LC_CTYPE", "LC_NUMERIC", "LC_TIME", "LC_COLLATE",
              "LC_MONETARY", "LC_MESSAGES", "LC_PAPER", "LC_NAME",
              "LC_ADDRESS", "LC_TELEPHONE", "LC_MEASUREMENT",
              "LC_IDENTIFICATION"]


def sh():
    s = fs.Shell(fs.VFS(), peer="203.0.113.77")
    s.exec_mode = True
    return s


def run(s, cmd):
    out = s.run(cmd)
    err = "".join(s._err)
    s._err.clear()
    return out, err, s.last_rc


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-52s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


def parsed(out):
    d = {}
    for line in out.strip().splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            d[k] = v
    return d


def t_the_shape_matches_glibcs():
    """LANG, LANGUAGE, twelve categories, LC_ALL last -- in that order."""
    out, _err, rc = run(sh(), "locale")
    eq("locale rc", rc, 0)
    keys = [l.split("=", 1)[0] for l in out.strip().splitlines()]
    eq("field order", keys, ["LANG", "LANGUAGE"] + CATEGORIES + ["LC_ALL"])


def t_lc_all_overrides_everything():
    """The bug this sweep started from."""
    for cmd in ("LC_ALL=C locale", "export LC_ALL=C; locale"):
        out, _e, _rc = run(sh(), cmd)
        d = parsed(out)
        eq("%s: LC_ALL is reported" % cmd[:16], d.get("LC_ALL"), "C")
        for cat in CATEGORIES:
            eq("%s: %s follows LC_ALL" % (cmd[:16], cat), d.get(cat), '"C"')
        eq("%s: LANG is untouched" % cmd[:16], d.get("LANG"), "C.UTF-8")


def t_env_and_locale_cannot_disagree():
    """Whatever `echo $LC_ALL` says, `locale` has to say the same."""
    s = sh()
    run(s, "export LC_ALL=C")
    shown, _e, _rc = run(s, "echo $LC_ALL")
    out, _e, _rc = run(s, "locale")
    eq("the two agree", parsed(out).get("LC_ALL"), shown.strip())


def t_an_explicit_category_is_unquoted():
    """glibc quotes derived values and leaves explicit ones bare."""
    out, _e, _rc = run(sh(), "export LC_TIME=C; locale")
    d = parsed(out)
    eq("LC_TIME is bare", d.get("LC_TIME"), "C")
    eq("LC_CTYPE is still derived and quoted", d.get("LC_CTYPE"),
       '"C.UTF-8"')
    eq("LC_ALL stays empty", d.get("LC_ALL"), "")


def t_a_category_beats_lang_but_not_lc_all():
    s = sh()
    out, _e, _rc = run(s, "export LC_TIME=C LC_ALL=C.UTF-8; locale")
    d = parsed(out)
    eq("LC_ALL wins over the category", d.get("LC_TIME"), '"C.UTF-8"')


def t_an_uninstalled_locale_is_reported():
    """Accepting one in silence said it was fine. glibc names three
    categories on stderr and prints the values anyway."""
    out, err, rc = run(sh(), "LC_ALL=xx_YY.UTF-8 locale")
    eq("still exits 0", rc, 0)
    for cat in ("LC_CTYPE", "LC_MESSAGES", "LC_ALL"):
        check("warns about %s" % cat,
              "locale: Cannot set %s to default locale: "
              "No such file or directory" % cat in err, err[:80])
    eq("and prints the value regardless", parsed(out).get("LC_ALL"),
       "xx_YY.UTF-8")


def t_a_known_locale_is_quiet():
    for val in ("C", "C.UTF-8", "POSIX"):
        _o, err, _rc = run(sh(), "LC_ALL=%s locale" % val)
        eq("%s produces no warning" % val, err.strip(), "")


def t_locale_a_names_something_that_exists():
    """`locale -a` listed C.utf8 with no /usr/lib/locale on the box."""
    s = sh()
    out, _e, rc = run(s, "locale -a")
    eq("locale -a rc", rc, 0)
    names = out.split()
    eq("the set glibc ships without the locales package", sorted(names),
       ["C", "C.utf8", "POSIX"])
    o2, _e, rc2 = run(s, "ls /usr/lib/locale")
    eq("and the data directory is there", (o2.split(), rc2),
       (["C.utf8"], 0))
    o3, _e, rc3 = run(s, "test -d /usr/lib/locale/C.utf8 && echo yes")
    eq("C.utf8 is a directory", (o3.strip(), rc3), ("yes", 0))


def t_the_payloads_own_preamble():
    """The exact line the live recon opens with, and what it then reads."""
    s = sh()
    out, _e, _rc = run(
        s, "( export LANG=C LC_ALL=C; echo \"$LANG|$LC_ALL\"; "
           "locale | grep '^LC_MESSAGES' )")
    lines = out.strip().splitlines()
    eq("the subshell exports both", lines[0], "C|C")
    eq("and LC_MESSAGES follows", lines[1], 'LC_MESSAGES="C"')


def t_charmaps_still_answer():
    out, _e, rc = run(sh(), "locale -m")
    eq("locale -m rc", rc, 0)
    check("names UTF-8", "UTF-8" in out.split(), out[:60])


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("t_")]


def main():
    for t in TESTS:
        try:
            t()
        except Exception as exc:                              # noqa: BLE001
            check(t.__name__, False, "crashed: %r" % (exc,))
    print("passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL[:6]))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
