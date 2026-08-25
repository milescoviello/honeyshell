#!/usr/bin/env python3
"""mysql's output format depends on the terminal, and `select 1` has to work.

Five actors have read /var/www/.env off this box. The next thing anyone does
with a database credential is confirm it, and confirming it means

    ssh host "mysql -u p2p_app -p'...' -e 'select 1'"

which answered **ERROR 1064, syntax error**. So the credential worked, the
server accepted it, and then claimed not to understand the most basic
statement in SQL. `select now()` was the same.

And the format was wrong for that whole shape of invocation. mysql picks its
output from isatty(stdout): a terminal gets the box drawing, anything else
gets tab-separated columns with one header line, and `-t` forces the box
either way. This looked only at -B/-N, so an exec channel -- which has no
pty, and is how every one of these credentials has actually been used -- got
box drawing where the real client sends tabs. Anything reading the second
column got "|".

Measured against mariadb 12.3 in a container, both with and without a tty.
The scalar values below are that measurement:

    select 1          1 / 1              select 1+1      1+1 / 2
    select 'x'        x / x              select 100/4    100/4 / 25.0000
    select 1 as n     n / 1              select 1/3      1/3 / 0.3333
    select NULL as a  a / NULL           select 7%3      7%3 / 1

`/` yields DECIMAL with four decimal places while + - * and % stay integral,
which is the one arithmetic answer that did not match at first.

Usage:  python3 sqlttytest.py
"""

import sys

import fakeshell as F

CHECKS, FAILS = [], []

#: The scalar and format checks go over the local socket as root, which
#: needs no credential and works whether or not the persona is present.
#: The published fork deliberately leaves wordpress.py behind, and the
#: accepted DB password is derived from it -- so a suite that insisted on
#: the .env credential failed there for a reason that has nothing to do
#: with what it is testing.
SOCK = "mysql p2p_dist"
CRED = "mysql -u p2p_app -p'changeme-in-your-own-build' p2p_dist"

#: query -> (header, value). Measured on mariadb 12.3, batch mode.
SCALARS = [
    ("select 1", "1", "1"),
    ("SELECT 1", "1", "1"),
    ("select 1+1", "1+1", "2"),
    ("select 5*2", "5*2", "10"),
    ("select 10-3", "10-3", "7"),
    ("select 7%3", "7%3", "1"),
    ("select 100/4", "100/4", "25.0000"),
    ("select 10/2", "10/2", "5.0000"),
    ("select 1/3", "1/3", "0.3333"),
    ("select (1+2)*3", "(1+2)*3", "9"),
    ("select 'x'", "x", "x"),
    ("select 'hello world'", "hello world", "hello world"),
    ("select 1 as n", "n", "1"),
    ("select 2*3 as six", "six", "6"),
    ("select NULL as a", "a", "NULL"),
]


def check(name, got, want):
    CHECKS.append(name)
    if got != want:
        FAILS.append((name, got, want))


def sh(exec_mode=True):
    """exec_mode True == no pty, which is what an ssh exec channel gives."""
    s = F.Shell()
    s.exec_mode = exec_mode
    return s


def q(s, sql, flags="", who=None):
    return s.run('%s %s -e "%s" 2>/dev/null'
                 % (who or SOCK, flags, sql)).strip()


def bait_works(s):
    """Whether the .env credential authenticates here.

    False in the published fork, where the persona module that defines the
    password is not included. The checks that depend on it say so and skip
    rather than failing for an unrelated reason.
    """
    # Probed with version(), not `select 1`: `select 1` is one of the
    # things under test, so using it here made "the scalar path is broken"
    # indistinguishable from "there is no persona" and silently skipped the
    # credential checks on any build that had the bug.
    return "MariaDB" in q(s, "select version()", who=CRED) \
        or bool(q(s, "select version()", who=CRED))


def t_scalar_selects():
    """The connectivity check, and the arithmetic beside it."""
    s = sh()
    for sql, head, val in SCALARS:
        check("%s" % sql, q(s, sql), "%s\n%s" % (head, val))


def t_two_columns_are_tab_separated():
    s = sh()
    check("select 42, 7", q(s, "select 42, 7"), "42\t7\n42\t7")


def t_the_format_follows_the_terminal():
    """The half that was wrong for every real invocation."""
    e, i = sh(True), sh(False)
    out_e = q(e, "show tables")
    out_i = q(i, "show tables")
    check("an exec channel gets no box drawing", "+---" in out_e, False)
    check("...and a header line then plain rows",
          out_e.splitlines()[0], "Tables_in_p2p_dist")
    check("an interactive shell gets the box", out_i.startswith("+--"), True)
    check("...with the header between rules",
          "| Tables_in_p2p_dist" in out_i, True)
    # -t forces the box even with no terminal, and -B forces batch even with
    # one. Both measured.
    check("-t forces the box on an exec channel",
          q(e, "show tables", "-t").startswith("+--"), True)
    check("-B forces batch in an interactive shell",
          "+---" in q(i, "show tables", "-B"), False)
    check("-N drops the header",
          q(e, "show tables", "-N").splitlines()[0], "wp_commentmeta")


def t_the_bait_credential_still_works():
    """The whole point: the password the box hands out has to be accepted."""
    s = sh()
    if not bait_works(s):
        # No persona module, so there is no advertised credential to accept.
        check("skipped: no persona in this tree", True, True)
        return
    check("the .env credential is accepted",
          q(s, "select 1", who=CRED), "1\n1")
    bad = s.run("mysql -u p2p_app -pWRONGPASS -e 'select 1' 2>&1")
    check("a wrong password is denied", "ERROR 1045 (28000)" in bad, True)
    check("...and names the user",
          "'p2p_app'@'localhost'" in bad, True)
    # And the credential the file advertises is the one in the file.
    env = s.run("grep DB_PASSWORD /var/www/.env").strip()
    check("the password tried is the password advertised",
          env.split("=", 1)[1] if "=" in env else "", "changeme-in-your-own-build")


def t_what_we_do_not_model_still_errors():
    """A wrong answer is worse than a syntax error, so guessing is refused."""
    s = sh()
    for sql in ("select sleep(1)", "select benchmark(10,md5('x'))",
                "select load_file('/etc/passwd')"):
        out = s.run('%s -e "%s" 2>&1' % (SOCK, sql))
        check("%s is not invented" % sql,
              "ERROR" in out, True)


def t_pipe_inside_a_session_is_still_treated_as_a_terminal():
    """A known limitation, asserted rather than hidden.

    Real mysql looks at isatty(stdout), so `mysql -e ... | cat` in an
    interactive session is batch mode. This shell does not track a command's
    position in a pipeline, so it still sees a terminal and prints the box.

    Asserted as-is on purpose: if pipelines ever become representable this
    check fails, which is the signal to fix the format decision in
    cmd_mysql and delete this test. A comment would have been read by
    nobody; sweep 157 had exactly this arrangement pay off.
    """
    i = sh(False)
    piped = i.run("%s -e 'select 1' 2>/dev/null | cat" % SOCK)
    check("known limitation: a pipe still gets the box", "+---" in piped, True)


def main():
    for fn in (t_scalar_selects,
               t_two_columns_are_tab_separated,
               t_the_format_follows_the_terminal,
               t_the_bait_credential_still_works,
               t_what_we_do_not_model_still_errors,
               t_pipe_inside_a_session_is_still_treated_as_a_terminal):
        fn()
    for name, got, want in FAILS:
        print("  FAIL %-48s got %r want %r" % (name, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("sqlttytest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
