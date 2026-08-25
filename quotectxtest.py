#!/usr/bin/env python3
"""Does an operator inside quotes stay inside quotes?

Sweep 147. Three places asked "is this operator in this text" with a plain
substring search, which cannot tell an operator from the same characters
sitting inside a quoted string:

    if "$'" in word         swallowed the $ in `echo 'a$'`
    if "|&" in text         rewrote `echo 'a|&b'` into a pipeline
    text.find("<(")         expanded `echo 'x<(y)'` to x/dev/fd/63

The first cost the most. A `$` immediately before a closing single quote is
the shape of every anchored regex, so `grep -o 'b$'` matched twice instead of
once and `tr -d '$'` received an empty argument and deleted nothing -- wrong
answers from everyday commands, which a script acts on without knowing.

The `|&` one is the worst in kind rather than in reach: it does not mangle a
word, it rewrites the text into a **different command**, turning a quoted
string into a pipeline with stderr merged.

How each was found is the useful part. The `$'` bug surfaced because a real
/etc/profile called a real run-parts with a regex ending in `$` -- nothing in
the sketched image had ever had that shape. The other two were found by
grepping for the *shape* of the first rather than waiting for a symptom, which
took two minutes and found twice as many. All three now share one predicate,
`find_unquoted`, because three copies of one question is how they came to
disagree with bash in three different ways.

Every expectation here is diffed against the host's real bash.

Run from `honeypot/`.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-52s %s" % (name, detail))


def ours(script):
    s = fs.Shell(fs.VFS(), user="root", peer="198.51.100.7")
    del s._err[:]
    out = s.run(script)
    del s._err[:]
    return out


def real(script):
    return subprocess.run(["bash", "--noprofile", "--norc", "-c", script],
                          capture_output=True, text=True, timeout=15,
                          cwd="/tmp").stdout


def differential(label, script):
    a, b = ours(script), real(script)
    check("%s: %s" % (label, script), a == b, "ours=%r bash=%r" % (a, b))


# -- quoted text is literal ----------------------------------------------

def t_a_quoted_operator_is_just_characters():
    for sc in ("echo 'a|&b'", 'echo "a|&b"', "echo 'x<(y)'", 'echo "x>(y)"',
               "echo 'proc<(sub)'", "echo 'a$'", "echo \"a$\"",
               "echo 'one$two$'", "echo 'a$$'"):
        differential("quoted", sc)


def t_the_everyday_commands_that_were_wrong():
    """These are the ones that matter: a trailing $ is every anchored regex."""
    for sc in ("echo abcb | grep -o 'b$'",
               "echo 'one$two$' | tr -d '$'",
               "printf 'ab\\nb\\n' | grep -n 'b$'",
               "echo 'a$' | sed 's/[$]/D/'"):
        differential("regex", sc)


# -- ...and the real operators still work ---------------------------------

def t_the_operators_themselves_still_run():
    """Over-correcting would be worse than the bug: these are the constructs
    the quoted forms were being mistaken for."""
    for sc in ("echo hi |& cat",
               "cat <(echo from-procsub)",
               "diff <(echo a) <(echo a) && echo same",
               "wc -l < <(printf 'x\\ny\\n')",
               "echo $'A\\tB'",
               "echo $'\\x41'"):
        differential("operator", sc)


def t_quoted_and_real_in_one_line():
    """The case a naive fix gets wrong in the other direction."""
    for sc in ("echo 'a|&b' |& cat",
               "cat <(echo 'x<(y)')",
               "echo 'a$' ; echo abcb | grep -o 'b$'"):
        differential("mixed", sc)


# -- the predicate itself -------------------------------------------------

def t_find_unquoted_reads_quote_state():
    f = getattr(fs, "find_unquoted", None)
    if f is None:
        check("fakeshell exposes find_unquoted", False, "absent")
        return
    cases = [
        ("a |& b", "|&", 2),
        ("echo 'a|&b'", "|&", -1),
        ('echo "a|&b"', "|&", -1),
        ("echo 'a|&b' |& c", "|&", 12),
        ("x<(y)", "<(", 1),
        ("'x<(y)'", "<(", -1),
        ("echo 'a$'", "$'", -1),
        ("echo $'a'", "$'", 5),
        ("a\\'b |& c", "|&", 5),
    ]
    for text, needle, want in cases:
        got = f(text, needle)
        check("find_unquoted(%r, %r) == %d" % (text, needle, want),
              got == want, "got %d" % got)


def t_one_predicate_not_three():
    """The three sites share it, so they cannot drift apart again."""
    src = open(os.path.join(HERE, "fakeshell.py"), encoding="utf-8").read()
    check("the |& site uses it", 'find_unquoted(text, "|&")' in src)
    check("the procsub site uses it", 'find_unquoted(text, "<(")' in src)
    # Match executable lines, not prose. find_unquoted's own docstring quotes
    # both blind patterns as examples of the bug it exists to prevent, so a
    # plain substring search over the source finds them there and reports a
    # defect that is a comment. Anchor on the statement form instead.
    code = [l.rstrip() for l in src.splitlines()
            if l.strip().endswith(":") or l.strip().endswith(")")]
    check("no blind |& substring test left",
          not any(l.strip() == 'if "|&" in text:' for l in code))
    check("no blind procsub find left",
          not any(l.strip().startswith("i = text.find(\"<(\")")
                  or l.strip().startswith("j = text.find(\">(\")")
                  for l in code))


def main():
    for name, fn in sorted(globals().items()):
        if name.startswith("t_") and callable(fn):
            try:
                fn()
            except Exception as exc:                          # noqa: BLE001
                check(name, False, "crashed: %r" % (exc,))
    print("\npassed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL[:8]))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
