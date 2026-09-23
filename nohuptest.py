"""nohup only takes over a stream that is a terminal.

An attacker detaching a payload runs `nohup ./x &` or `nohup ./x >/dev/null`,
and on the exec channel they are almost always using, nohup changes nothing
at all: no notice, no nohup.out, output straight back to them.

We created nohup.out unconditionally. So `nohup ./payload` over an exec
channel swallowed the attacker's output into a file they never asked for and
handed back an empty string, and `nohup cmd > out.txt` left a stray
nohup.out beside out.txt that a real box does not create.

Measured on the guest (Debian 13.6, coreutils 9.7):

  no tty (exec channel)   output passes through, no file, no notice
  tty                     nohup: ignoring input and appending output to
                          'nohup.out'                     -- file created 0600
  tty, stdout redirected  nohup: ignoring input and redirecting stderr to
                          stdout                          -- no file created

That third message is the one worth having: with stdout sent elsewhere but
stderr still on the terminal, real nohup points stderr at stdout and says
so. We had no such branch.

Underneath was a second defect. The flag nohup consulted to decide whether
the caller had already redirected stdout, `_nohup_redirected`, was declared
with a comment claiming the redirection machinery set it -- and nothing in
the tree ever assigned it. It was permanently False, so the branch could
never be taken. It is now set from the redirections parsed for the command
being run, and restored afterwards so a nested dispatch cannot leak it.

Usage:  python3 nohuptest.py
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


def shell(tty):
    """A session with a pty, or an exec channel with none."""
    sh = fakeshell.Shell(vfs=fakeshell.VFS(), peer="198.51.100.51",
                         peer_port=43110)
    sh.exec_mode = not tty
    sh.run("mkdir -p /tmp/nh && cd /tmp/nh")
    return sh


def run(sh, cmd):
    """(stdout, rc, stderr-from-this-command). Guarded."""
    before = len(getattr(sh, "_err", []) or [])
    try:
        out = sh.run(cmd)
    except Exception as exc:                                   # noqa: BLE001
        return ("<raised %s: %s>" % (type(exc).__name__, exc), -1, "")
    err = "".join((getattr(sh, "_err", []) or [])[before:])
    return (out, getattr(sh, "last_rc", None), err.strip())


def ls(sh):
    out, _, _ = run(sh, "ls")
    return sorted(out.split())


# ------------------------------------------- exec channel: nohup is inert
sh = shell(tty=False)
out, rc, err = run(sh, "nohup echo hello")
check("exec: the command's output comes back", out.strip(), "hello",
      "this is what an attacker running `nohup ./payload` sees; we were "
      "returning an empty string and filing their output away")
check("exec: exit status is the command's", rc, 0)
check("exec: no notice is printed", err, "",
      "with no terminal there is nothing for nohup to take over")
check("exec: no nohup.out is created", ls(sh), [],
      "the guest creates none here")

run(sh, "nohup echo redir > o.txt")
check("exec: redirect writes only the named file", ls(sh), ["o.txt"])
check("exec: ...with the right content", run(sh, "cat o.txt")[0].strip(),
      "redir")

# --------------------------------------------- pty: nohup takes stdout
sh = shell(tty=True)
out, rc, err = run(sh, "nohup echo hello")
check("tty: stdout is taken, not returned", out.strip(), "")
check("tty: the notice names the file", err,
      "nohup: ignoring input and appending output to 'nohup.out'")
check("tty: nohup.out is created", ls(sh), ["nohup.out"])
check("tty: ...and holds the output",
      run(sh, "cat nohup.out")[0].strip(), "hello")
check("tty: ...created 0600, not 0644",
      run(sh, "stat -c %a nohup.out")[0].strip(), "600",
      "GNU nohup creates it private")

run(sh, "nohup echo second")
check("tty: a second run appends rather than truncating",
      run(sh, "cat nohup.out")[0].split(), ["hello", "second"])

# ------------------------- pty with stdout redirected: the third message
sh = shell(tty=True)
out, rc, err = run(sh, "nohup echo redir > o.txt")
check("tty+redirect: nohup does not claim stdout", ls(sh), ["o.txt"],
      "a stray nohup.out beside the file the caller asked for is a tell, "
      "and it is what the unset _nohup_redirected flag produced")
check("tty+redirect: ...and says it is moving stderr instead", err,
      "nohup: ignoring input and redirecting stderr to stdout")
check("tty+redirect: the named file has the output",
      run(sh, "cat o.txt")[0].strip(), "redir")

# The invariant, counted: no spelling of "stdout goes elsewhere" may leave
# a nohup.out behind. A new redirect form that forgets this fails here.
strays = {}
for form in ("> a.txt", ">> b.txt", "> /dev/null", "| cat"):
    s = shell(tty=True)
    run(s, "nohup echo x %s" % form)
    if "nohup.out" in ls(s):
        strays[form] = ls(s)
check("no redirect form leaves a stray nohup.out", strays, {},
      "checked 4 forms; each must leave stdout where the caller put it")

# ------------------------------------------------------- exit statuses
sh = shell(tty=False)
check("nohup false exits 1", run(sh, "nohup false")[1], 1)
out, rc, err = run(sh, "nohup nosuchcmd")
check("a missing command exits 127", rc, 127,
      "127 is what a script branches on")
check("...and names it the way nohup does",
      "nohup: failed to run command 'nosuchcmd': No such file or directory"
      in err, True, "got %r" % err[:120])
out, rc, err = run(sh, "nohup")
check("no operand exits 125", rc, 125,
      "125 distinguishes nohup's own failure from the command's")
check("...and points at --help", "Try 'nohup --help'" in err, True,
      "got %r" % err[:120])

# ------------------------------- ssh -tt: an exec channel WITH a terminal
# `ssh -tt host 'cmd'` asks for a pty and then execs. The guest treats it as
# a terminal, so nohup takes stdout over there just as in a login shell.
# Keying only on exec_mode got this backwards.
sh = fakeshell.Shell(vfs=fakeshell.VFS(), peer="198.51.100.52")
sh.exec_mode = True
sh.has_pty = True
sh.run("mkdir -p /tmp/nh && cd /tmp/nh")
check("ssh -tt counts as a terminal", sh.stdout_is_tty, True,
      "an exec channel that asked for a pty has one")
out, rc, err = run(sh, "nohup echo ttyexec")
check("ssh -tt: nohup takes stdout", out.strip(), "")
check("ssh -tt: ...and names the file", err,
      "nohup: ignoring input and appending output to 'nohup.out'")
check("ssh -tt: ...and the file holds the output",
      run(sh, "cat nohup.out")[0].strip(), "ttyexec")

# and an exec channel that asked for no pty is still not a terminal
sh = shell(tty=False)
check("plain exec is still not a terminal", sh.stdout_is_tty, False)

# ------------------------------------------- the flag does not leak out
sh = shell(tty=True)
run(sh, "nohup echo x > o.txt")
out, rc, err = run(sh, "nohup echo y")
check("a redirected nohup does not disarm the next one", err,
      "nohup: ignoring input and appending output to 'nohup.out'",
      "the flag is per-command and must be restored, or one redirect "
      "silently changes how every later nohup behaves")

for f in FAILS:
    print(" ", f)
print("   nohup: %d checks, %d differ" % (len(CHECKS), len(FAILS)))
sys.exit(1 if FAILS else 0)
