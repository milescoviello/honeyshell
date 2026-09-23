"""Every keystroke, the way a real ssh session answers it.

The interactive loop handled Enter, backspace and ctrl-c. Everything else
was appended to the command line and echoed, so pressing Up printed ^[[A
and then tried to run it as a command -- which is the first thing anyone
does after typing a command wrong, and it is visible within seconds.

The editor is a module rather than a block inside the socket loop precisely
so this file can exist: keystrokes go in, the bytes that would go to the
channel come out, and none of it needs a connection. That includes the
cases that only happen on a wire -- an escape sequence split across two
packets arrives as two feeds here, exactly as it would from two recv calls.

The rule under all of it: no key may ever leave its own escape bytes in the
buffer. A command line that ends up containing ^[[A is a box that is not
running readline, whatever else it claims.

Usage:  python3 lineedittest.py
"""

import sys

import lineedit

CHECKS, FAILS = [], []
P = "root@web01:~# "


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want, "\n  -- " + note if note else ""))


def ed(history=None):
    return lineedit.LineEditor(history=list(history or []))


def feed(e, *chunks):
    """Push chunks through, returning (all output, all submitted lines)."""
    out, lines = "", []
    for c in chunks:
        o, ls = e.feed(c, P)
        out += o
        lines += ls
    return out, lines


# ------------------------------------------------------- ordinary typing
e = ed()
out, lines = feed(e, "echo hello")
check("typing fills the buffer", e.buf, "echo hello")
check("...and echoes what was typed", out, "echo hello")
check("...and submits nothing yet", lines, [])
out, lines = feed(e, "\r")
check("enter submits the line", lines, ["echo hello"])
check("...and clears the buffer", e.buf, "")
check("...and sends a newline", out, "\r\n")

# ------------------------------------------------- the bug this fixes
for name, seq in (("up", "\x1b[A"), ("down", "\x1b[B"),
                  ("right", "\x1b[C"), ("left", "\x1b[D"),
                  ("home", "\x1b[H"), ("end", "\x1b[F"),
                  ("delete", "\x1b[3~"), ("f1", "\x1bOP"),
                  ("unknown csi", "\x1b[99Z")):
    e2 = ed()
    feed(e2, "ls", seq)
    check("%s leaves no escape bytes in the line" % name,
          "\x1b" in e2.buf or "[" in e2.buf.replace("ls", ""), False,
          "got %r -- this is what made Up print ^[[A" % e2.buf)

# ------------------------------- the keystrokes a real attacker sent
# 203.0.113.76, 2026-08-28 05:00:27, in an interactive session while
# fingerprinting the box: one Up, then six arrows in a SINGLE packet, then
# another Up. The pattern -- up, down, down, up, up, up -- is a person
# scrolling their history, not a script. The shell logged all of it as
# unknown_command and answered "command not found" to the raw bytes.
#
# The burst matters on its own: six sequences in one recv is a different
# path from six separate reads, and it is the path the wire actually took.
OBSERVED = ("\x1b[A", "\x1b[A\x1b[B\x1b[B\x1b[A\x1b[A\x1b[A", "\x1b[A")
real_hist = ["ls -la", "cd /var/www", "df -h", "systemctl status nginx",
             "mysql -u p2p_app -p"]
e = ed(real_hist)
out, lines = feed(e, *OBSERVED)
check("the arrows a real attacker sent run nothing", lines, [],
      "every one of these was executed as a command before this existed")
check("...and leave no escape bytes on the line", "\x1b" in e.buf, False)
check("...and land on a real history entry", e.buf in real_hist, True)
check("...specifically the third one back", e.buf, "cd /var/www")

e = ed(real_hist)
feed(e, "\x1b[A\x1b[B\x1b[B\x1b[A\x1b[A\x1b[A")
check("six sequences in one packet are six keys, not one blob", e.buf,
      "df -h",
      "up,down,down,up,up,up from the newest entry lands three back")

# ------------------------------------------------------------- history
h = ["ls -la", "whoami", "cat /etc/passwd"]
e = ed(h)
feed(e, "\x1b[A")
check("up recalls the most recent command", e.buf, "cat /etc/passwd")
feed(e, "\x1b[A")
check("up again goes further back", e.buf, "whoami")
feed(e, "\x1b[A")
check("...and further", e.buf, "ls -la")
feed(e, "\x1b[A")
check("up stops at the oldest", e.buf, "ls -la")
feed(e, "\x1b[B")
check("down comes forward again", e.buf, "whoami")
feed(e, "\x1b[B", "\x1b[B")
check("down past the newest restores what was being typed", e.buf, "")

e = ed(h)
feed(e, "half typed", "\x1b[A")
check("browsing history stashes the unfinished line", e.buf,
      "cat /etc/passwd")
feed(e, "\x1b[B")
check("...and coming back restores it", e.buf, "half typed",
      "readline keeps the line you were on")

e = ed()
feed(e, "\x1b[A")
check("up with no history does nothing", e.buf, "")

# the editor must use the shell's list, not a copy of its own
shared = ["first"]
e = ed()
e.history = shared
shared.append("second")
feed(e, "\x1b[A")
check("history is shared, not copied", e.buf, "second",
      "if Up and the history builtin read different lists they will "
      "disagree about what was run")

# --------------------------------------------------- cursor movement
e = ed()
feed(e, "abcd")
feed(e, "\x1b[D", "\x1b[D")
check("left moves the cursor", e.pos, 2)
feed(e, "X")
check("typing inserts at the cursor", e.buf, "abXcd")
check("...and the cursor follows the insertion", e.pos, 3)
feed(e, "\x1b[C")
check("right moves forward", e.pos, 4)
feed(e, "\x01")
check("ctrl-a goes to the start", e.pos, 0)
feed(e, "\x05")
check("ctrl-e goes to the end", e.pos, len(e.buf))
feed(e, "\x02")
check("ctrl-b is left", e.pos, len(e.buf) - 1)
feed(e, "\x06")
check("ctrl-f is right", e.pos, len(e.buf))

e = ed()
feed(e, "abc", "\x1b[D")
feed(e, "\x7f")
check("backspace deletes before the cursor", e.buf, "ac")
check("...and moves the cursor back", e.pos, 1)
feed(e, "\x1b[3~")
check("delete removes under the cursor", e.buf, "a")

e = ed()
feed(e, "\x7f")
check("backspace on an empty line does nothing", e.buf, "")
check("...and does not move the cursor negative", e.pos, 0)

# ------------------------------------------------------- kill and yank
e = ed()
feed(e, "one two three", "\x17")
check("ctrl-w kills the word before the cursor", e.buf, "one two ")
feed(e, "\x15")
check("ctrl-u kills to the start", e.buf, "")

e = ed()
feed(e, "keep this", "\x01", "\x0b")
check("ctrl-k kills to the end", e.buf, "")

e = ed()
feed(e, "abcd", "\x14")
check("ctrl-t transposes the last two", e.buf, "abdc")

# ------------------------------------------------------ control signals
e = ed()
out, lines = feed(e, "half done", "\x03")
check("ctrl-c prints ^C", "^C\r\n" in out, True)
check("...and abandons the line", e.buf, "")
check("...and asks the caller for a fresh prompt", lines, [None],
      "the line is not run; the prompt is reprinted")

e = ed()
feed(e, "\x04")
check("ctrl-d on an empty line ends the session", e.done, True)
e = ed()
feed(e, "text", "\x04")
check("ctrl-d with text on the line does not", e.done, False)

e = ed()
out, _ = feed(e, "abc", "\x0c")
check("ctrl-l clears the screen", "\x1b[H\x1b[2J" in out, True)
check("...and repaints the line being typed", e.buf, "abc")

# --------------------------------------------- sequences split on the wire
e = ed(["earlier"])
out, _ = feed(e, "\x1b")
check("a lone ESC is held, not treated as a key", e.pending, "\x1b")
check("...and nothing is echoed for it", out, "")
feed(e, "[A")
check("...and the sequence completes on the next packet", e.buf, "earlier",
      "a recv boundary can fall anywhere; readline does not care")

e = ed(["earlier"])
feed(e, "\x1b[", "A")
check("a split after the bracket also completes", e.buf, "earlier")

e = ed()
feed(e, "\x1b[2", "00~pasted\x1b[201~")
check("bracketed paste markers are swallowed", e.buf, "pasted",
      "a terminal that pastes sends these around the text")

# --------------------------------------------------------- word motion
e = ed()
feed(e, "alpha beta gamma", "\x1bb")
check("alt-b goes back a word", e.pos, 11)
feed(e, "\x1bb")
check("...and again", e.pos, 6)
feed(e, "\x1bf")
check("alt-f goes forward a word", e.pos, 10)

# --------------------------------------------------------------- limits
e = lineedit.LineEditor(history=[], max_len=8)
feed(e, "123456789012")
check("the line is capped", len(e.buf), 8,
      "an unbounded line is a memory hole on a box that gets scanned")

# tab has no completion table to offer, but must not insert a tab either
e = ed()
feed(e, "ls", "\t")
check("tab does not land in the buffer", e.buf, "ls")

# ^D must not swallow what came after it in the same chunk.
#
# feed() returns the moment it sees ^D on an empty line, and it used to
# drop the rest of the chunk on the floor. That was invisible while ^D
# always meant an immediate logout. Once a command can consume the ^D as
# its end of input -- `cat > f`, a pasted script, ^D, and then more
# commands, all in one paste -- everything after it is real input, and
# losing it means the commands an attacker typed never run.
e = ed()
out, lines = feed(e, "one\n\x04echo after\n")
check("the line before ^D is submitted", lines, ["one"])
check("^D is recorded", e.done, True)
check("what followed ^D is kept, not dropped", e.pending, "echo after\n")
# and a second call with nothing new drains it
out2, lines2 = feed(e, "")
check("the remainder comes back on the next feed", lines2, ["echo after"])
check("...and pending is empty afterwards", e.pending, "")

# ^D with nothing after it still just ends the line
e = ed()
out, lines = feed(e, "solo\n\x04")
check("^D at the very end leaves nothing pending", e.pending, "")
check("...and still sets done", e.done, True)

for f in FAILS:
    print(" ", f)
print("   lineedit: %d checks, %d differ" % (len(CHECKS), len(FAILS)))
sys.exit(1 if FAILS else 0)
