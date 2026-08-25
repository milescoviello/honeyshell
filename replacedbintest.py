#!/usr/bin/env python3
"""A binary the attacker replaced has to be the binary that runs.

This is the anti-forensics step every miner performs, and the box was
quietly undoing it. One actor here replaced 23 binaries in a single session

    ps  top  htop  kill  pkill  killall  xkill  pgrep  lsof  strace  gdb
    netstat  ss  w  who  whoami  users  finger  last  loginctl  id
    uptime  watch

then ran `chattr +i` on /bin, /usr/bin, /sbin and /usr/sbin, installed a
miner as srbminer.service, and ran `ps`. It got the real process list back,
with its own miner in it, out of a file it had overwritten two seconds
earlier.

Four readers, two answers:

    cat /usr/bin/ps      the attacker's script
    file /usr/bin/ps     POSIX shell script, ASCII text executable
    stat -c %s           22
    ps                   behaved exactly like procps

The sharpest form of it: `/usr/bin/ps` already ran the replacement, because
executing a path has always read the file at that path. Only the bare name
`ps` went to the built-in. Two spellings of one file, and the one an
attacker types is the one that lied.

Every stock binary in this persona is an ELF stub with no content -- all 413
of them, checked -- so "content and no ELF header at that path" is an
unambiguous statement that the file is not the one the package installed.
Dispatch now runs it.

What deliberately does *not* change: `command -v`, `which`, `type` and
`dpkg -S` all still name the path and the owning package, because replacing
a file does not remove it from dpkg's list. That is what `dpkg -V` is for,
and it is the difference an operator uses to find the tampering.

Usage:  python3 replacedbintest.py
"""

import sys

import fakeshell

CHECKS, FAILS = [], []

HIDER = "printf '#!/bin/sh\\necho HIDDEN\\n' > %s; chmod 755 %s"


def check(name, got, want):
    CHECKS.append(name)
    if got != want:
        FAILS.append((name, got, want))


def box():
    fs = fakeshell.VFS()
    return fs, fakeshell.Shell(vfs=fs, peer="203.0.113.9", peer_port=44321)


def replace(sh, path):
    sh.run(HIDER % (path, path))


def main():
    # -- the baseline the rule depends on -----------------------------------
    fs, sh = box()
    bins = [p for p in fs.node_paths()
            if p.startswith(("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/"))]
    real = [p for p in bins
            if (fs.nodes.get(p) and not fs.nodes[p].is_dir
                and fs.nodes[p].link is None)]
    check("the persona has binaries", len(real) > 300, True)
    # If a stock binary ever ships with script content, the rule below
    # starts misfiring on it -- so the rule's precondition is a check.
    scripted = [p for p in real
                if fs.nodes[p].elf is None and fs.nodes[p].content]
    check("no stock binary ships as a script", scripted, [])

    # -- the headline -------------------------------------------------------
    fs, sh = box()
    sh.run("mkdir -p /root/.x; echo x > /root/.x/miner; "
           "chmod 755 /root/.x/miner; nohup /root/.x/miner &")
    check("ps sees the miner before the swap",
          sh.run("ps -eo args --no-headers | grep -c /root/.x/miner").strip(),
          "1")
    replace(sh, "/usr/bin/ps")
    check("ps runs what is at /usr/bin/ps", sh.run("ps"), "HIDDEN\n")
    check("...whatever arguments it is given", sh.run("ps -ef"), "HIDDEN\n")
    check("...and the miner is no longer listed",
          "/root/.x/miner" in sh.run("ps -ef"), False)
    # One inode, two names: /bin is a symlink into /usr/bin.
    check("the pre-merge spelling runs it too", sh.run("/bin/ps"), "HIDDEN\n")
    check("...and so does the absolute path",
          sh.run("/usr/bin/ps"), "HIDDEN\n")

    # -- the readers that must NOT change -----------------------------------
    check("command -v still names the path",
          sh.run("command -v ps").strip(), "/usr/bin/ps")
    check("which agrees", sh.run("which ps").strip(), "/usr/bin/ps")
    check("type agrees", sh.run("type ps").strip(), "ps is /usr/bin/ps")
    check("dpkg still owns the path", sh.run("dpkg -S /usr/bin/ps").strip(),
          "procps: /usr/bin/ps")
    check("file describes what is actually there",
          "shell script" in sh.run("file /usr/bin/ps"), True)
    check("stat reports the replacement's size",
          sh.run("stat -c %s /usr/bin/ps").strip(), "22")

    # -- an unreplaced neighbour is untouched -------------------------------
    check("top still works", sh.run("top -bn1 | head -1").startswith("top - "),
          True)
    check("...and still sees the miner",
          "/root/.x/miner" in sh.run("top -bn1"), True)

    # -- it survives the reconnect ------------------------------------------
    # Anti-forensics that undoes itself on the next login is worse than none.
    fs2 = fakeshell.VFS()
    fs2.load_journal(fs.dump_journal())
    sh2 = fakeshell.Shell(vfs=fs2, peer="203.0.113.9", peer_port=44322)
    check("the replacement survives a reconnect", sh2.run("ps"), "HIDDEN\n")

    # -- the whole toolkit, as it was actually used -------------------------
    fs, sh = box()
    toolkit = ["ps", "top", "pgrep", "pkill", "killall", "lsof", "netstat",
               "ss", "w", "who", "whoami", "last", "id", "uptime"]
    for name in toolkit:
        path = "/usr/bin/%s" % name
        if not fs.exists(path):
            continue
        replace(sh, path)
    for name in toolkit:
        if not fs.exists("/usr/bin/%s" % name):
            continue
        check("%s runs the replacement" % name, sh.run(name), "HIDDEN\n")

    # -- and a name we never implemented behaves the same --------------------
    fs, sh = box()
    replace(sh, "/usr/bin/curl")
    check("a replaced curl is the attacker's curl",
          sh.run("curl http://example.com"), "HIDDEN\n")

    # -- restoring the file restores nothing by magic ------------------------
    # A replaced binary that is then deleted is gone, not silently back.
    fs, sh = box()
    replace(sh, "/usr/bin/ps")
    sh.run("rm -f /usr/bin/ps")
    check("deleting the replacement leaves no ps",
          sh.run("command -v ps").strip(), "")
    check("...and running it fails", sh.run("ps"), "")

    # -- an immutable bin directory does not resurrect the original ---------
    # The real actor chattr'd the directories after replacing the files. If
    # that put the stock binary back, the whole sequence would undo itself.
    fs, sh = box()
    replace(sh, "/usr/bin/ps")
    sh.run("chattr -R +i /usr/bin")
    check("ps is still the replacement after chattr +i",
          sh.run("ps"), "HIDDEN\n")
    check("lsattr shows the directory locked",
          "i" in sh.run("lsattr -d /usr/bin").split()[0], True)

    for name, got, want in FAILS:
        print("  FAIL %-58s got %r want %r" % (name, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("replacedbintest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
