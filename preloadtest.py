#!/usr/bin/env python3
"""What the dynamic loader says before a command runs.

`/etc/ld.so.preload` is the classic userland-rootkit persistence -- the file
you write so that every process on the box loads your library before libc.
It was already logged here as `persistence_write`, so the *capture* side was
right. What was missing is that the box behaves no differently once it
exists.

On a real box, if the library named in it cannot be opened, ld.so prints

    ERROR: ld.so: object '/usr/lib/libx.so' from /etc/ld.so.preload cannot
    be preloaded (cannot open shared object file): ignored.

before every dynamically linked program, and the program then runs normally
with its exit status unchanged. Writing the file before staging the library
is an ordering mistake people make, and on a real box it is deafening --
every command they type answers with it, twice over if a subshell is
involved. Here it was silent: `cat /etc/ld.so.preload` said a library was
preloaded and the entire rest of the box behaved as though it were not.

`LD_PRELOAD` in the environment does the same with a different source label.
Both wordings measured on debian:trixie:

    echo /usr/lib/libnope.so > /etc/ld.so.preload
    id      -> ERROR: ... from /etc/ld.so.preload ... ; then uid=0(root) ...
    LD_PRELOAD=/usr/lib/libnope.so id
            -> ERROR: ... from LD_PRELOAD ... ; then uid=0(root) ...

Two properties that matter as much as the wording: the message is on
**stderr**, so `2>/dev/null` hides it and a script that only reads stdout
never sees it; and the command still succeeds, so nothing downstream
branches differently. A rootkit whose library *does* exist is silent, which
is the case the operator is aiming for.

Usage:  python3 preloadtest.py
"""

import sys

import fakeshell

CHECKS, FAILS = [], []
MSG = ("ERROR: ld.so: object '%s' from %s cannot be preloaded "
       "(cannot open shared object file): ignored.")


def check(name, got, want):
    CHECKS.append(name)
    if got != want:
        FAILS.append((name, got, want))


def box():
    fs = fakeshell.VFS()
    return fs, fakeshell.Shell(vfs=fs, peer="203.0.113.9", peer_port=44321)


def main():
    # -- a box with no preload file is quiet --------------------------------
    fs, sh = box()
    check("no /etc/ld.so.preload to begin with",
          fs.exists("/etc/ld.so.preload"), False)
    check("...and commands say nothing extra",
          sh.run("id 2>&1"), "uid=0(root) gid=0(root) groups=0(root)\n")

    # -- the file, naming a library that is not there -----------------------
    fs, sh = box()
    sh.run("echo /usr/lib/libx.so > /etc/ld.so.preload")
    want = MSG % ("/usr/lib/libx.so", "/etc/ld.so.preload")
    out = sh.run("id 2>&1")
    check("the loader complains", out.splitlines()[0] if out else "", want)
    check("...and the command still runs",
          "uid=0(root)" in out, True)
    check("...with its exit status unchanged",
          sh.run("id >/dev/null 2>&1; echo $?").strip(), "0")
    check("it is on stderr, not stdout",
          "ERROR: ld.so" in sh.run("id 2>/dev/null"), False)
    check("...so 2>/dev/null hides it entirely",
          sh.run("id 2>/dev/null"), "uid=0(root) gid=0(root) groups=0(root)\n")

    # Every external command, not just the first.
    two = sh.run("id 2>&1; uname -s 2>&1")
    check("every command gets it", two.count("ERROR: ld.so"), 2)

    # Builtins are not execs and the loader never sees them.
    check("a builtin says nothing", sh.run("echo hi 2>&1"), "hi\n")
    check("...nor does cd", sh.run("cd /tmp 2>&1"), "")

    # -- the file naming a library that IS there ----------------------------
    # The case a working rootkit is aiming for: silence.
    sh.run("mkdir -p /usr/lib; echo x > /usr/lib/libx.so")
    check("a library that exists preloads quietly",
          sh.run("id 2>&1"), "uid=0(root) gid=0(root) groups=0(root)\n")
    sh.run("rm -f /usr/lib/libx.so")
    check("...and removing it brings the error back",
          sh.run("id 2>&1").splitlines()[0], want)

    # -- several libraries, and the file surviving a reconnect --------------
    fs, sh = box()
    sh.run("printf '/opt/a.so\\n/opt/b.so\\n' > /etc/ld.so.preload")
    out = sh.run("id 2>&1")
    check("one line per unopenable library", out.count("ERROR: ld.so"), 2)
    check("the first names a.so", MSG % ("/opt/a.so", "/etc/ld.so.preload")
          in out, True)
    check("the second names b.so", MSG % ("/opt/b.so", "/etc/ld.so.preload")
          in out, True)
    fs2 = fakeshell.VFS()
    fs2.load_journal(fs.dump_journal())
    sh2 = fakeshell.Shell(vfs=fs2, peer="203.0.113.9", peer_port=44322)
    check("the preload file survives a reconnect",
          sh2.run("cat /etc/ld.so.preload").count("/opt/"), 2)
    check("...and so does what it does to every command",
          sh2.run("id 2>&1").count("ERROR: ld.so"), 2)

    # -- LD_PRELOAD in the environment --------------------------------------
    fs, sh = box()
    sh.run("export LD_PRELOAD=/opt/evil.so")
    out = sh.run("id 2>&1")
    check("LD_PRELOAD complains with its own source label",
          out.splitlines()[0] if out else "",
          MSG % ("/opt/evil.so", "LD_PRELOAD"))
    check("...and the command still runs", "uid=0(root)" in out, True)
    sh.run("unset LD_PRELOAD")
    check("unsetting it stops the message",
          sh.run("id 2>&1"), "uid=0(root) gid=0(root) groups=0(root)\n")

    # A colon-separated list is several libraries, as ld.so reads it.
    sh.run("export LD_PRELOAD=/opt/a.so:/opt/b.so")
    check("a colon-separated list is two libraries",
          sh.run("id 2>&1").count("ERROR: ld.so"), 2)

    # -- writing it is still recorded as persistence ------------------------
    seen = []
    fs = fakeshell.VFS()
    sh = fakeshell.Shell(vfs=fs, peer="203.0.113.9", peer_port=44321,
                         log=lambda **ev: seen.append(ev))
    sh.run("echo /opt/rk.so > /etc/ld.so.preload")
    kinds = [e for e in seen if e.get("event") == "persistence_write"]
    check("writing the file is logged as persistence", bool(kinds), True)
    check("...and named as the preload mechanism",
          any(e.get("kind") == "ld_preload" for e in kinds), True)

    # -- tripwire: a prefix assignment loses redirected stderr --------------
    # Found while measuring the LD_PRELOAD case and NOT fixed here, because
    # it is not about preloading at all. `VAR=value cmd 2>&1` runs the
    # command in a recursive frame after the outer one has already stripped
    # the redirections, and the outer returns that frame's value directly --
    # skipping the epilogue that would fold stderr into stdout. So the
    # error is produced and then thrown away:
    #
    #     ls /nosuchdir 2>&1          -> "ls: cannot access ..."   (right)
    #     FOO=1 ls /nosuchdir 2>&1    -> ""                        (wrong)
    #     FOO=1 ls /nosuchdir 2>/tmp/b -> the file is empty
    #
    # Real bash prints the error in all three. This matters well beyond
    # preloading: `DEBIAN_FRONTEND=noninteractive apt-get install -y x 2>&1`
    # and `LC_ALL=C sort ... 2>&1` are both this shape, and today's most
    # common recon payload wraps its whole probe in
    # `$( ( export LANG=C LC_ALL=C; ... ) 2>&1 )`. Fixing it means
    # restructuring where the command runner applies assignments relative to
    # redirections, which is its own sweep. Asserted here so it cannot
    # change unnoticed -- if this fails, either it was fixed (good, update
    # this) or something else moved.
    fs, sh = box()
    check("plain redirection works",
          "No such file or directory" in sh.run("ls /nosuchdir 2>&1"), True)
    check("KNOWN GAP: a prefix assignment loses redirected stderr",
          sh.run("FOO=1 ls /nosuchdir 2>&1"), "")
    check("...including to a file",
          sh.run("FOO=1 ls /nosuchdir 2>/tmp/b; cat /tmp/b"), "")
    check("...and the same for LD_PRELOAD's own message",
          sh.run("LD_PRELOAD=/opt/x.so id 2>&1"),
          "uid=0(root) gid=0(root) groups=0(root)\n")

    for name, got, want in FAILS:
        print("  FAIL %-58s got %r want %r" % (name, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("preloadtest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
