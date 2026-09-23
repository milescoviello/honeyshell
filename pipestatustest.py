"""$? and ${PIPESTATUS[@]} answer the same question, and must agree.

Two readers of one fact -- "did what just ran succeed?" -- and a script can
consult either. A loader that pipes a downloader into a shell reads
${PIPESTATUS[0]} precisely because $? would only tell it about the last
stage. Diicot's competitor sweep, seen live on 2026-08-28, is this shape:

    ps aux | awk '$3 > 40.0 && $11 !~ /sshd/ {print $2}' | while read pid ...

PIPESTATUS was only assigned when the command actually contained a `|`, so
a simple command left the *previous* pipeline's array in place and the box
contradicted itself:

                        real bash        this box
    true|true|true      (0 0 0)          (0 0 0)
    true;               (0)   n=1        (0 0 0)   n=3
    false;              (1)              (0 0 0)
    ${PIPESTATUS[0]}    0                1        <- from a pipeline two
                                                     commands earlier

`false; echo $? ${PIPESTATUS[@]}` answering "1" and "0 0 0" in one breath is
a one-line tell, and a stale ${PIPESTATUS[0]} silently misreports a stage
that never ran in this command at all.

Every expected value below was measured on the guest, which is Debian 13.6
running bash 5.2. The subtle ones:

    ! false      $? is 0 but PIPESTATUS is (1) -- negation changes only $?
    x=1          an assignment is a command: it sets PIPESTATUS to (0)
    f(){ return 7; }; f    -> (7), not the status of anything inside f

Usage:  python3 pipestatustest.py
"""

import sys

import fakeshell

CHECKS, FAILS = [], []


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want, "\n  -- " + note if note else ""))


def shell():
    return fakeshell.Shell(vfs=fakeshell.VFS(), peer="198.51.100.44",
                           peer_port=43001)


def run(sh, cmd):
    """stdout, or a sentinel. A suite must survive the tree it is testing."""
    try:
        return sh.run(cmd).strip()
    except Exception as exc:                                   # noqa: BLE001
        return "<raised %s: %s>" % (type(exc).__name__, exc)


def probe(sh, cmd):
    """Run `cmd`, then report "<rc> <pipestatus>" the way bash would."""
    run(sh, cmd)
    return run(sh, 'echo "$? ${PIPESTATUS[@]}"')


sh = shell()

# ------------------------------------------------- pipelines, measured
for label, cmd, want in (
        ("true | false", "true | false", "1 0 1"),
        ("false | true", "false | true", "0 1 0"),
        ("false | false | true", "false | false | true", "0 1 1 0"),
        ("true | true | true", "true | true | true", "0 0 0 0"),
        ("(exit 3) | (exit 5)", "(exit 3) | (exit 5)", "5 3 5")):
    check("%s -> $? and PIPESTATUS" % label, probe(sh, cmd), want)

# ------------------------------- a simple command sets it too (the finding)
for label, cmd, want in (("true", "true", "0 0"),
                         ("false", "false", "1 1"),
                         ("assignment", "x=1", "0 0"),
                         ("subshell", "(exit 4)", "4 4"),
                         ("&& list", "true && false", "1 1"),
                         ("compound if", "if true; then :; fi", "0 0"),
                         ("compound for", "for i in 1 2; do :; done", "0 0")):
    check("%s -> $? and PIPESTATUS" % label, probe(sh, cmd), want,
          "a simple command gets a one-element array holding its own status")

# ---------------------------------------------- negation is $?-only
check("! false leaves PIPESTATUS at the real status",
      probe(sh, "! false"), "0 1",
      "bash negates $? and leaves PIPESTATUS alone")
check("! true likewise", probe(sh, "! true"), "1 0")

# ------------------------------------------------------------- functions
run(sh, "f() { return 7; }")
check("a function's status reaches PIPESTATUS", probe(sh, "f"), "7 7")

# ------------------------------------------- the array really is an array
# Read in ONE command: the `echo` that reads PIPESTATUS is itself a command
# and replaces it, so a second echo sees (0). Confirmed on the guest, which
# prints "0//" when the indexes are read one command too late -- so these
# have to be asked together or the test measures the echo, not the pipeline.
run(sh, "true | false | true")
check("length and indexes, read in the same command",
      run(sh, 'echo "${PIPESTATUS[0]}/${PIPESTATUS[1]}/${PIPESTATUS[2]} '
              'len=${#PIPESTATUS[@]}"'),
      "0/1/0 len=3")
run(sh, "true | false | true")
run(sh, "echo consumed > /dev/null")
check("...and an intervening command replaces it, as bash does",
      run(sh, 'echo "${PIPESTATUS[0]}/${PIPESTATUS[1]}/${PIPESTATUS[2]}"'),
      "0//",
      "the guest prints exactly this: the echo reset the array to its own "
      "one-element status")

# The count is the assertion: a stale array is exactly the bug, so the
# length must track the command that just ran, for every width.
widths = {}
for n in (1, 2, 3, 4):
    run(sh, " | ".join(["true"] * n))
    widths[n] = run(sh, 'echo ${#PIPESTATUS[@]}')
check("PIPESTATUS width follows the current command", widths,
      {1: "1", 2: "2", 3: "3", 4: "4"},
      "a width that does not shrink back to 1 is the previous pipeline's "
      "array surviving into the next command")

run(sh, "false | false")
run(sh, "x=2")
check("an assignment after a pipeline replaces the array",
      run(sh, 'echo "${#PIPESTATUS[@]} ${PIPESTATUS[@]}"'), "1 0",
      "the pipeline's (1 1) must not outlive the command after it")
check("...and the out-of-range index is empty, not stale",
      run(sh, 'echo "[${PIPESTATUS[1]}]"'), "[]")

# ------------------------------------------------------------- pipefail
check("pipefail makes a failed producer the pipeline's status",
      probe(sh, "set -o pipefail; false | true"), "1 1 0")
run(sh, "set +o pipefail")
check("...and without it the last stage still wins",
      probe(sh, "false | true"), "0 1 0")

# --------------------------------------- the construct seen in the wild
out = run(sh, "printf '1\\n2\\n3\\n' | while read n; do printf '%s,' \"$n\"; done")
check("a pipeline into while-read sees every line", out, "1,2,3,",
      "this is the tail of the competitor sweep Diicot runs on landing")
check("...and reports a status for both stages",
      run(sh, 'echo "$? ${#PIPESTATUS[@]}"'), "0 2")
check("read splits into multiple names",
      run(sh, "printf 'a b c\\n' | while read p q r; do echo \"$r-$q-$p\"; done"),
      "c-b-a")

# ------------------------------------------------ $? and PIPESTATUS agree
# For a single command the two readers must never disagree: PIPESTATUS[0]
# is $? by definition. This is the invariant the finding violated.
#
# `if false; then :; fi` is deliberately not in this list. PIPESTATUS holds
# the last *pipeline* actually run, and an if whose condition is false and
# which has no else runs nothing after the condition -- so bash reports
# $? of 0 and PIPESTATUS[0] of 1, and they are supposed to differ.
# Measured, on the reference bash:
#
#     if false; then :; fi         rc=0 pipestatus=1
#     while false; do :; done      rc=0 pipestatus=1
#     if false; then :; else :; fi rc=0 pipestatus=0
#     if true; then false; fi      rc=1 pipestatus=1
#
# The pair is checked against bash directly below instead, which is the
# only way to assert a rule with a real exception in it.
disagree = []
for cmd in ("true", "false", "(exit 9)", "x=5", "f",
            "true && false", "false || true"):
    run(sh, cmd)
    pair = run(sh, 'echo "$?:${PIPESTATUS[0]}"')
    if ":" in pair and pair.split(":")[0] != pair.split(":")[1]:
        disagree.append("%s -> %s" % (cmd, pair))
for _c, _want in (("if false; then :; fi", "0:1"),
                  ("while false; do :; done", "0:1"),
                  ("if false; then :; else :; fi", "0:0"),
                  ("if true; then false; fi", "1:1")):
    run(sh, _c)
    check("%s -> $?:PIPESTATUS[0]" % _c,
          run(sh, 'echo "$?:${PIPESTATUS[0]}"'), _want,
          "measured on the reference bash; the two are allowed to differ "
          "here because no pipeline ran after the condition")

check("no simple command has $? disagreeing with PIPESTATUS[0]",
      disagree, [],
      "these are two spellings of one question and a script may use either")

for f in FAILS:
    print(" ", f)
print("   pipestatus: %d checks, %d differ" % (len(CHECKS), len(FAILS)))
sys.exit(1 if FAILS else 0)
