#!/usr/bin/env python3
"""A malformed line ran its good half; bash runs none of it.

Found by feature-testing rather than by reading logs -- 23 quoting and
expansion cases driven against real bash on the guest. Twenty-one matched
exactly. The one that did not was the whole of bash's syntax checking:

    echo ok && echo "dangling
      emulator  rc=0  out='ok\\ndangling\\n'
      bash      rc=2  out=''

bash parses the entire input before it runs anything, so a quoting error
means nothing executes. This box ran the good half, and then the bad half
too. Fifteen malformed inputs were tried and all fifteen differed: the
emulator either accepted them at rc 0 or reported a shell keyword as a
missing command --

    if true; then echo hi
      emulator  rc=127  bash: if true; then echo hi: command not found

which no bash has ever said.

## why this is not hypothetical

Of the 1461 distinct commands in the live ssh log, `bash -n` on the guest
refuses four. One of them has **35 occurrences from 14 addresses** --
2.57.122.x, 92.118.39.x, 195.178.110.x, 80.94.92.x and 203.0.113.48 --
and it is the dominant loader's *first* command, the
`export PATH=...; uname=$(...)` recon preamble, whose substitution leaves
a quote open. Real bash answers

    bash: -c: line 6: unexpected EOF while looking for matching `''

and runs nothing. This box ran it 35 times, so every one of those sessions
forked from a real box at the loader's first instruction and the loader's
own error handling never fired. The other three are our own traffic:
two from 10.10.10.1 and one from the box's own public address.

## the shape of the fix, and why it is a subset

A first draft also balanced if/for/while/case and flagged stray tokens.
It produced **26 false positives** over those same 1461 commands, because
`dd if=/dev/sda` tokenises `if` as the keyword unless you know `=` binds it
into one word, and because a case pattern's `)` is legitimate. A false
positive here silently refuses a real attacker's command, which loses the
capture the box exists for -- strictly worse than the bug. So the check is
quotes, backticks, `$(` and `$((` only: **0 false positives over 1461**,
and it catches the 35-occurrence case with bash's exact message.

Three measured details that would be wrong if guessed:

  * the prefix. bash uses `bash: -c: line N:` for *syntax* errors and
    plain `bash: line N:` for runtime ones, over the same ssh exec. The
    existing runtime prefix was already right; only this path takes `-c:`.
  * the line numbers. A quote or backtick names the line it *opened* on;
    `$((` names its opening line; `$(` names the line *after*. Verified on
    one-line and three-line inputs for each -- three different rules, none
    of them "the last line".
  * exec_mode only. Interactive bash does not error on an open quote at
    all: `bash --norc -i` answers with a `> ` PS2 continuation prompt and
    waits, and only errors because stdin hits EOF. Erroring in the
    interactive path would be a new wrong answer, and honest continuation
    is separate work. All 35 malformed attacker commands arrived over
    exec.

Usage:  python3 syntaxtest.py
"""

import sys

import fakeshell as fs

CHECKS, FAILS = [], []

# Every row measured against bash on the guest, a real Debian trixie,
# invoked the way sshd invokes it.
REFUSED = [
    ('echo "unclosed',
     "bash: -c: line 1: unexpected EOF while looking for matching `\"'"),
    ("echo 'unclosed",
     "bash: -c: line 1: unexpected EOF while looking for matching `''"),
    ('echo `unclosed',
     "bash: -c: line 1: unexpected EOF while looking for matching ``'"),
    ('echo $(unclosed',
     "bash: -c: line 2: unexpected EOF while looking for matching `)'"),
    ('echo $((1+',
     "bash: -c: line 1: unexpected EOF while looking for matching `)'"),
    ('echo "a" "b',
     "bash: -c: line 1: unexpected EOF while looking for matching `\"'"),
    ('echo ok && echo "dangling',
     "bash: -c: line 1: unexpected EOF while looking for matching `\"'"),
    ('cut -d" -f2 /var/log/nginx/access.log.1 | sort -u | wc -l',
     "bash: -c: line 1: unexpected EOF while looking for matching `\"'"),
]

# The line a construct is blamed on, measured three ways because the rule
# differs per construct and none of them is "the last line".
LINES = [
    ('echo "x\n', 1, '"'),
    ('echo a\necho b\necho "x\n', 3, '"'),
    ('echo "x\necho b\necho c\n', 1, '"'),
    ('echo $(x\n', 2, ')'),
    ('echo a\necho b\necho $(x\n', 4, ')'),
    ('echo $((1+\n', 1, ')'),
    ('echo a\necho b\necho $((1+\n', 3, ')'),
    ('echo a\necho `x\necho c\n', 2, '`'),
]

# Valid input that a naive balance check gets wrong. Each of these was a
# real false positive in the first draft.
ACCEPTED = [
    "dd if=/dev/sda bs=512 count=1 2>/dev/null | wc -c",
    "case $(uname -m) in x86_64|amd64) A=amd64 ;; *) A=other ;; esac; echo $A",
    'v=$( ( echo nested ) ); echo "$v"',
    'for f in a.gz b; do case $f in *.gz) C=zcat;; *) C=cat;; esac; done; echo $C',
    'cat <<"PY"\na comment with an odd \' apostrophe\nPY',
    "cat <<EOF\nunbalanced ( and \" inside a heredoc\nEOF",
    'echo ok && echo fine',
    'x=abcdef; echo ${x:2:3}${x##*b}',
    'echo $((2**10)) $(echo nested)',
    'echo ${PATH:-} ${NOPE:+set}',
]


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want, "\n  -- " + note if note else ""))


def syntax_error(text):
    """The checker, or Nones on a build that has not got it yet.

    Guarded because a suite that raises against the previous commit
    reports a traceback instead of the failures it was written to find --
    and takes the rest of its own run down with it. The first draft of
    this file did exactly that against HEAD.
    """
    fn = getattr(fs.Shell, "_syntax_error", None)
    if fn is None:
        return (None, None, None)
    try:
        return fn(text)
    except Exception:                                          # noqa: BLE001
        return (None, None, None)


def run_exec(cmd):
    """(stdout, stderr, rc) over the exec path, which is how sshd runs it."""
    try:
        sh = fs.Shell(fs.VFS(), peer="203.0.113.88")
        sh.exec_mode = True
        out = sh.run(cmd)
    except Exception as exc:                                   # noqa: BLE001
        return "<%s>" % exc, "", None
    err = "".join(sh._err)
    sh._err = []
    return out, err, sh.last_rc


# ============================ malformed input runs nothing and exits 2
for cmd, msg in REFUSED:
    out, err, rc = run_exec(cmd)
    check("refused: %s" % cmd[:34], rc, 2,
          "bash parses the whole input first; nothing should run")
    check("...and ran nothing: %s" % cmd[:26], out, "",
          "this is the half the box used to execute anyway")
    check("...with bash's message: %s" % cmd[:22], err.strip(), msg,
          "measured on the guest over ssh exec")

# The production case, verbatim in shape: a substitution that leaves a
# quote open several lines in.
PROD = ("export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:"
        "/sbin:/bin:${PATH:-} LC_ALL=C LANG=C\n"
        "uname=$(for c in uname /bin/uname /usr/bin/uname 'b\n")
out, err, rc = run_exec(PROD)
check("the 35-occurrence loader preamble is refused", rc, 2,
      "14 addresses sent this; the box ran it every time")
check("...and runs none of it", out, "")
check("...naming the line the quote opened on",
      "line 2:" in err, True, "got %r" % err.strip()[:80])

# ================================== the line a construct is blamed on
for text, want_line, ch in LINES:
    msgs, rc, ln = syntax_error(text)
    check("line for %r" % text.replace("\n", "\\n")[:26], ln, want_line,
          "quote names where it opened, $(( likewise, $( the line after")
    check("...and the char it wants: %r" % ch,
          bool(msgs) and ("matching `%s'" % ch) in msgs[0], True)

# ============================= valid input is untouched, and still runs
for cmd in ACCEPTED:
    msgs, rc, ln = syntax_error(cmd)
    check("not refused: %s" % cmd[:38], msgs, None,
          "every one of these was a false positive in the first draft; "
          "refusing a real command loses the capture")
    out, err, rcx = run_exec(cmd)
    check("...and still exits 0: %s" % cmd[:30], rcx, 0, "err=%r" % err[:60])

# ================== the interactive path is deliberately left alone
# bash prints a PS2 `> ` there and waits; it does not error. Verified
# with `bash --norc -i` on the guest.
sh = fs.Shell(fs.VFS(), peer="203.0.113.88")
out = sh.run('echo "unclosed')
err = "".join(sh._err)
sh._err = []
check("interactive does not take the syntax path", sh.last_rc, 0,
      "erroring here would be a new wrong answer: bash prompts instead")
check("...and produces no bash: -c: message", "bash: -c:" in err, False)

# ============ the second bug, which this check is what exposed
# cmd_bash ran its operand through .strip("'\""), so a -c script that
# began or ended with a quote character lost it: `bash -c 'echo "hi"'`
# reached the child as `echo "hi`. The child tolerated the unterminated
# quote because nothing checked syntax, so the corruption was invisible --
# until the check above started refusing the emulator's own plumbing and
# envtest went red. Every row verified against bash on the guest.
for cmd, want in (
        ('bash -c \'echo "hi"\'', "hi\n"),
        ('bash -c \'echo "a="\'', "a=\n"),
        ("bash -c 'env | grep -c \"^HOME=\"'", "1\n"),
        ("sh -c 'echo \"a=\"'", "a=\n"),
        ("bash -c 'echo hi'", "hi\n"),
        ('bash -c "echo hi"', "hi\n"),
        ("bash -lc 'echo hi'", "hi\n"),
):
    out, err, rc = run_exec(cmd)
    check("-c keeps its quotes: %s" % cmd[:30], (out, rc), (want, 0),
          "err=%r -- a quote eaten off either end used to corrupt the "
          "child's script silently" % err[:60])

# ...and a -c script that really is unbalanced is still refused, so the
# fix above did not simply disable the check for this path.
out, err, rc = run_exec('bash -c \'echo "unclosed\'')
check("an unbalanced -c script is still refused", rc, 2)
check("...and runs nothing", out, "")

# =========== a runtime error keeps its own prefix, without the -c
out, err, rc = run_exec("nosuchcmd")
check("a runtime error still exits 127", rc, 127)
check("...and uses the plain prefix, not -c:",
      err.strip(), "bash: line 1: nosuchcmd: command not found",
      "bash uses -c: for syntax errors only -- measured both ways over "
      "the same ssh exec")

print("%d checks, %d failed" % (len(CHECKS), len(FAILS)))
for f in FAILS:
    print(f)
sys.exit(1 if FAILS else 0)
