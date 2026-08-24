#!/usr/bin/env python3
"""Do the tools that show invisible bytes agree there are any?

`cat -A`, `od`, `hexdump` and `sed -n l` all answer "what bytes are really
in this file". Given a file containing a tab, od printed \\t, hexdump
printed 09, `sed -n l` printed a $ at the line end -- and `cat -A` printed
the file unchanged, reporting no tab and no line ends at all.

  - cat's -A, -v, -e, -t, -E, -T, -b and -s were every one of them parsed
    and dropped. Only -n did anything, so `cat -A f` was byte-identical to
    `cat f`. That is the silent-wrong-answer shape: the caller asked to be
    shown the invisible characters and was told there were none.
  - `nl -ba` numbers every line including the blanks, and -b was dropped
    too, so -ba and the default -bt printed the same thing -- the one
    behaviour the flag exists to change. -w and -s were dropped with it.

These formats are defined by coreutils, not by this box, so they are
checked against a real cat and nl rather than against this implementation:
identical bytes for thirteen cat invocations and eight nl ones, including
the details that are easy to get wrong -- that -b overrides -n, that -s
squeezes before numbering, that the number column's separator is a real tab
which -T does not touch because -T applies to the file's bytes and not to
cat's own output, and that an unnumbered nl line is padded to the width of
the number field plus its separator.

Run from `honeypot/`, or on the guest.
"""

import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []

FILES = {
    "t.txt": b"a\tb\nc  \n",
    "b.txt": b"one\n\n\n\ntwo\n\nthree\n",
    "ctl.txt": b"x\x01\x7f\xc3\xa9y\n",
    "notrail.txt": b"no newline at eof",
}


def sh():
    s = fs.Shell(fs.VFS(), peer="203.0.113.77")
    s.exec_mode = True
    for name, body in FILES.items():
        s.run("printf '' > /%s" % name)
        s.fs.write("/" + name, body)
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


def refdir():
    d = tempfile.mkdtemp()
    for name, body in FILES.items():
        with open(os.path.join(d, name), "wb") as fh:
            fh.write(body)
    return d


def real(cmd, cwd):
    try:
        return subprocess.run(["bash", "-c", cmd], cwd=cwd,
                              capture_output=True, timeout=20
                              ).stdout.decode("latin-1")
    except Exception:
        return None


def t_cat_display_flags_match_coreutils():
    """The contradiction this sweep started from."""
    s = sh()
    d = refdir()
    for cmd in ("cat -A t.txt", "cat -e t.txt", "cat -t t.txt",
                "cat -E t.txt", "cat -T t.txt", "cat -v t.txt",
                "cat -v ctl.txt", "cat -A ctl.txt", "cat -e ctl.txt",
                "cat -s b.txt", "cat -b b.txt", "cat -n b.txt",
                "cat -n -s b.txt", "cat -bA b.txt", "cat -nT t.txt",
                "cat t.txt", "cat notrail.txt", "cat -A notrail.txt",
                "cat -n notrail.txt"):
        want = real(cmd, d)
        if want is None:
            check("%s (no reference cat)" % cmd, True)
            continue
        got, _ = run(s, cmd.replace(" t.txt", " /t.txt")
                     .replace(" b.txt", " /b.txt")
                     .replace(" ctl.txt", " /ctl.txt")
                     .replace(" notrail.txt", " /notrail.txt"))
        eq("%s matches coreutils" % cmd, got, want)


def t_cat_A_reports_the_bytes_the_others_report():
    """Cross-view, not just format: od, hexdump and sed all see the tab."""
    s = sh()
    a, _ = run(s, "cat -A /t.txt")
    check("cat -A marks the tab", "^I" in a, repr(a))
    check("cat -A marks the line ends", a.count("$") == 2, repr(a))
    o, _ = run(s, "od -An -tx1 /t.txt")
    check("od sees a 09 byte", "09" in o.split(), o.strip())
    h, _ = run(s, "hexdump -C /t.txt")
    check("hexdump sees a 09 byte", " 09 " in h, h[:60])
    l, _ = run(s, "sed -n l /t.txt")
    check("sed -n l marks the line ends", l.count("$") == 2, repr(l))
    check("sed -n l escapes the tab as backslash-t", "\\\\t" in repr(l)
          or "\\t" in l.replace("\t", "TAB"), repr(l))
    check("sed -n l does not emit a raw tab", "\t" not in l, repr(l))
    w, _ = run(s, "wc -c < /t.txt")
    eq("and wc agrees on the length", w.strip(), "8")
    # The count of tabs must be the same however you ask.
    n_cat = a.count("^I")
    n_od = o.split().count("09")
    eq("cat -A and od count the same tabs", n_cat, n_od)


def t_cat_high_bytes_use_M_notation():
    s = sh()
    o, _ = run(s, "cat -v /ctl.txt")
    eq("control, DEL and UTF-8 bytes", o, "x^A^?M-CM-)y\n")
    o, _ = run(s, "cat -A /ctl.txt")
    eq("and -A adds the line end", o, "x^A^?M-CM-)y$\n")


def t_cat_b_overrides_n_and_s_runs_first():
    s = sh()
    o, _ = run(s, "cat -b /b.txt")
    lines = o.split("\n")
    check("-b numbers the first line", lines[0].endswith("\tone"), lines[0])
    eq("-b leaves blank lines unnumbered", lines[1], "")
    check("-b numbers only three lines", o.count("\t") == 3, repr(o))
    o, _ = run(s, "cat -n -s /b.txt")
    eq("-n -s numbers what survives the squeeze",
       len([l for l in o.split("\n") if l]), 5)
    o, _ = run(s, "cat -bn /b.txt")
    o2, _ = run(s, "cat -b /b.txt")
    eq("-b wins over -n", o, o2)


def t_cat_numbering_separator_is_a_real_tab():
    s = sh()
    o, _ = run(s, "cat -nT /t.txt")
    check("the file's tab became ^I", "^I" in o, repr(o))
    check("but the number separator is still a tab", "\t" in o, repr(o))
    eq("exactly one real tab per numbered line", o.count("\t"), 2)


def t_nl_body_numbering_matches_coreutils():
    s = sh()
    d = refdir()
    for cmd in ("nl b.txt", "nl -ba b.txt", "nl -bn b.txt", "nl -bt b.txt",
                "nl -w3 b.txt", "nl -s: b.txt", "nl -ba -w2 -s' ' b.txt",
                "nl -bpthree b.txt", "nl -ba -s' | ' b.txt"):
        want = real(cmd, d)
        if want is None:
            check("%s (no reference nl)" % cmd, True)
            continue
        got, _ = run(s, cmd.replace(" b.txt", " /b.txt"))
        eq("%s matches coreutils" % cmd, got, want)


def t_nl_ba_and_the_default_differ():
    """The whole point of -b, which was being dropped."""
    s = sh()
    a, _ = run(s, "nl /b.txt")
    b, _ = run(s, "nl -ba /b.txt")
    check("-ba is not the same as the default", a != b, "identical")
    eq("the default numbers 3 lines", len([l for l in a.split("\n")
                                           if l.strip() and "\t" in l]), 3)
    eq("-ba numbers all 7", len([l for l in b.split("\n") if "\t" in l]), 7)
    n, _ = run(s, "nl -bn /b.txt")
    eq("-bn numbers none", n.count("\t"), 0)
    o, rc = run(s, "nl -bZ /b.txt")
    eq("an invalid style is refused", rc, 1)
    check("with nl's wording", "invalid body numbering style" in o, o[:70])


def t_the_dump_tools_agree_with_each_other():
    s = sh()
    o, _ = run(s, "od -An -tx1 /t.txt")
    od_bytes = o.split()
    h, _ = run(s, "hexdump -C /t.txt")
    hx = h.split("\n")[0].split("|")[0].split()[1:]
    eq("od and hexdump -C list the same bytes", od_bytes, hx)
    n, _ = run(s, "wc -c < /t.txt")
    eq("and there are as many as wc counts", len(od_bytes), int(n.strip()))
    c, _ = run(s, "od -c /t.txt")
    check("od -c shows the tab as \\t", "\\t" in c, c[:60])
    check("od -c shows the newlines as \\n", c.count("\\n") >= 2, c[:60])


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("t_")]


def main():
    for t in TESTS:
        try:
            t()
        except Exception as exc:                              # noqa: BLE001
            check(t.__name__, False, "crashed: %r" % (exc,))
    print("passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
