r"""grep kept only the last -e.

Fifty-fifth coherence sweep, found while verifying the kill sweep: a
throwaway `pgrep -x nginx | grep -v -e '^701$' -e '^702$'` printed
everything instead of filtering, which is not something grep does.

parse_opts returns a dict of option values, so a repeated option
overwrote the one before it. Only the LAST pattern survived:

    grep -e 701 -e 702        matched 702 only
    grep -e xmrig -e kinsing  matched kinsing only
    grep -v -e 701 -e 702     inverted the wrong set and PRINTED 701

The last of those is the dangerous shape. -v with several patterns is how
a script excludes things -- `ps aux | grep -v -e grep -e sshd` -- and
instead of hiding both it hid one and emitted the other, so the caller
acted on a line it had asked not to see. And `grep -e A -e B` is exactly
how a competitor scan looks for several miners at once, which is a
command this box gets sent.

-f had a second form of the same bug: it was declared as taking a value
and its file was never read, so the pattern list came out empty and grep
fell through to treating the first operand as the pattern -- searching
for the name of the file it was supposed to search.

--regexp= and clustered forms (`grep -ne foo -e bar`) go through the same
collector now, because they are the same option.

Every case below was measured against the real GNU grep on the dev host.

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []

SAMPLE = "701\n702\n4106\nxmrig\nkinsing\nsshd\n"
PATFILE = "xmrig\nkinsing\n"


def shell():
    s = fs.Shell(fs.VFS(), user="root", peer="203.0.113.77")
    s.exec_mode = True
    s.run(r"printf '701\n702\n4106\nxmrig\nkinsing\nsshd\n' > /tmp/g.txt")
    s.run(r"printf 'xmrig\nkinsing\n' > /tmp/pat.txt")
    s._err.clear()
    return s


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-48s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


def lines(s, cmd):
    return s.run(cmd).split()


# -- several -e are OR-ed ------------------------------------------------

def t_two_patterns_both_match():
    s = shell()
    eq("-e 701 -e 702", lines(s, "grep -e 701 -e 702 /tmp/g.txt"),
       ["701", "702"])
    eq("-e xmrig -e kinsing",
       lines(s, "grep -e xmrig -e kinsing /tmp/g.txt"), ["xmrig", "kinsing"])


def t_three_patterns():
    s = shell()
    eq("three -e", lines(s, "grep -e 701 -e xmrig -e sshd /tmp/g.txt"),
       ["701", "xmrig", "sshd"])


def t_anchored_patterns_survive():
    s = shell()
    eq("anchored -e", lines(s, "grep -e '^701$' -e '^702$' /tmp/g.txt"),
       ["701", "702"])


def t_order_follows_the_file_not_the_patterns():
    """grep prints matching lines in file order, not pattern order."""
    s = shell()
    eq("file order", lines(s, "grep -e kinsing -e 701 /tmp/g.txt"),
       ["701", "kinsing"])


# -- the dangerous one ---------------------------------------------------

def t_dash_v_hides_all_of_them():
    s = shell()
    eq("-v with two patterns",
       lines(s, "grep -v -e 701 -e 702 /tmp/g.txt"),
       ["4106", "xmrig", "kinsing", "sshd"])


def t_dash_v_does_not_print_what_it_was_asked_to_hide():
    s = shell()
    out = lines(s, "grep -v -e 701 -e 702 /tmp/g.txt")
    for hidden in ("701", "702"):
        check("-v really hides %s" % hidden, hidden not in out, str(out))


def t_the_ps_aux_idiom():
    """`ps aux | grep -v -e grep -e sshd` is the canonical use."""
    s = shell()
    out = s.run("ps aux | grep -v -e grep -e sshd | grep -c sshd").strip()
    eq("no sshd survives the filter", out, "0")


# -- clustered and long forms --------------------------------------------

def t_clustered_short_options():
    s = shell()
    eq("-ne 701 -e 702", lines(s, "grep -ne 701 -e 702 /tmp/g.txt"),
       ["1:701", "2:702"])


def t_attached_pattern():
    s = shell()
    eq("-e701 -e702", lines(s, "grep -e701 -e702 /tmp/g.txt"), ["701", "702"])


def t_long_regexp_option():
    s = shell()
    eq("--regexp= twice",
       lines(s, "grep --regexp=701 --regexp=702 /tmp/g.txt"), ["701", "702"])
    eq("--regexp spaced",
       lines(s, "grep --regexp 701 --regexp 702 /tmp/g.txt"), ["701", "702"])


# -- -f reads patterns from a file ---------------------------------------

def t_dash_f_reads_the_file():
    s = shell()
    eq("-f patterns", lines(s, "grep -f /tmp/pat.txt /tmp/g.txt"),
       ["xmrig", "kinsing"])


def t_dash_f_does_not_eat_the_operand():
    """With -f broken, grep searched for the name of the file instead."""
    s = shell()
    out = s.run("grep -f /tmp/pat.txt /tmp/g.txt")
    check("no path echoed as a match", "/tmp" not in out, out[:60])


def t_dash_f_missing_file():
    s = shell()
    out = s.run("grep -f /nope/pat.txt /tmp/g.txt")
    err = "".join(s._err)
    check("reports the missing pattern file",
          "No such file or directory" in (out + err), (out + err)[:70])
    eq("rc 2", s.last_rc, 2)


def t_dash_f_and_dash_e_combine():
    s = shell()
    eq("-f plus -e", lines(s, "grep -f /tmp/pat.txt -e 701 /tmp/g.txt"),
       ["701", "xmrig", "kinsing"])


# -- counts and the single-pattern path must not have moved --------------

def t_count_counts_all_matches():
    s = shell()
    eq("-c with two patterns",
       s.run("grep -c -e 701 -e 702 /tmp/g.txt").strip(), "2")


def t_single_pattern_unchanged():
    s = shell()
    eq("bare pattern", lines(s, "grep 701 /tmp/g.txt"), ["701"])
    eq("single -e", lines(s, "grep -e 701 /tmp/g.txt"), ["701"])
    eq("-E alternation", lines(s, "grep -E '701|702' /tmp/g.txt"),
       ["701", "702"])
    eq("no match rc", s.run("grep nosuchthing /tmp/g.txt; echo $?").strip(),
       "1")


def t_stdin_still_works():
    s = shell()
    eq("piped -e twice",
       s.run("cat /tmp/g.txt | grep -e 701 -e 702").split(), ["701", "702"])


def t_recursive_still_works():
    """-r was fixed in an earlier sweep; it must survive this one."""
    s = shell()
    s.run("mkdir -p /tmp/rd && printf 'xmrig here\\n' > /tmp/rd/a.txt")
    out = s.run("grep -r -e xmrig -e kinsing /tmp/rd")
    check("-r finds it", "xmrig" in out, out[:60])


TESTS = [t_two_patterns_both_match, t_three_patterns,
         t_anchored_patterns_survive, t_order_follows_the_file_not_the_patterns,
         t_dash_v_hides_all_of_them,
         t_dash_v_does_not_print_what_it_was_asked_to_hide,
         t_the_ps_aux_idiom, t_clustered_short_options, t_attached_pattern,
         t_long_regexp_option, t_dash_f_reads_the_file,
         t_dash_f_does_not_eat_the_operand, t_dash_f_missing_file,
         t_dash_f_and_dash_e_combine, t_count_counts_all_matches,
         t_single_pattern_unchanged, t_stdin_still_works,
         t_recursive_still_works]


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
