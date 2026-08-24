#!/usr/bin/env python3
"""File timestamps -- four clocks, not one.

The axis: when this box is asked "when did this file change?", the
answers have to be different questions. Every inode here carried a
single number that `stat` printed four times, so:

  touch -t 202001010000 payload

moved the *change* time back to 2020 as well. No filesystem can do that.
ctime is maintained by the kernel, cannot be set from userspace, and is
the one timestamp a timestomp cannot reach -- which is exactly why
`find -newerct`, `find -ctime -1` and `ls -lc` are the first three
things anyone runs on a box they think has been touched. All three
answered with the mtime, so the box agreed with the attacker's own
forgery and had no record that anything had been backdated.

Reference behaviour measured on the guest (Debian 13, ext4, relatime).
"""
import sys
import time
import fakeshell as F

FAILS, CHECKS = [], []


def check(label, got, want):
    CHECKS.append(label)
    if got != want:
        FAILS.append((label, got, want))


def sh(vfs=None):
    v = vfs or F.VFS()
    s = F.Shell(v, peer="198.51.100.23")
    s.exec_mode = True
    return v, s


def clocks(v, path):
    n = v.nodes[path]
    return n.atime, n.mtime, n.ctime, n.btime


def main():
    # -- a fresh file has all four equal, as a real one does -------------
    v, s = sh()
    s.run("echo hi > /tmp/f")
    a, m, c, b = clocks(v, "/tmp/f")
    check("new file: atime == mtime", a == m, True)
    check("new file: ctime == mtime", c == m, True)
    check("new file: btime == mtime", b == m, True)

    # -- the seeded image is internally consistent -----------------------
    v2 = F.VFS()
    bad = [p for p, n in v2.nodes.items()
           if n.ctime < n.mtime or n.btime > n.mtime or n.btime > n.ctime]
    check("no seeded file is born after it changed", bad[:3], [])

    # A box that logs people in has read /etc/passwd since it wrote it.
    n = v2.nodes["/etc/passwd"]
    check("/etc/passwd has been read since it was written", n.atime > n.mtime,
          True)
    check("/etc/passwd modify and change agree", n.ctime == n.mtime, True)

    # -- metadata changes move ctime and nothing else --------------------
    for cmd, label in (("chmod 600 /tmp/f", "chmod"),
                       ("chown daemon /tmp/f", "chown"),
                       ("chgrp daemon /tmp/f", "chgrp")):
        v, s = sh()
        s.run("echo hi > /tmp/f")
        a0, m0, c0, b0 = clocks(v, "/tmp/f")
        time.sleep(0.002)
        s.run(cmd)
        a1, m1, c1, b1 = clocks(v, "/tmp/f")
        check("%s moves ctime" % label, c1 > c0, True)
        check("%s leaves mtime" % label, m1 == m0, True)
        check("%s leaves atime" % label, a1 == a0, True)
        check("%s leaves btime" % label, b1 == b0, True)

    # -- the timestomp ---------------------------------------------------
    v, s = sh()
    s.run("echo payload > /tmp/p")
    time.sleep(0.002)
    s.run("touch -t 202001010000 /tmp/p")
    a, m, c, b = clocks(v, "/tmp/p")
    check("touch -t sets atime", int(a), 1577836800)
    check("touch -t sets mtime", int(m), 1577836800)
    check("touch -t cannot set ctime", c > 1577836800, True)
    check("ctime is now, not the forged date", abs(c - time.time()) < 5, True)
    check("stat reports the forged mtime",
          s.run("stat -c %Y /tmp/p").strip(), "1577836800")
    check("stat reports the real ctime",
          s.run("stat -c %Z /tmp/p").strip() != "1577836800", True)
    check("plain stat shows them differing",
          s.run("stat /tmp/p").count("2020-01-01"), 2)

    # -a and -m each move one clock. Both moving is how a careless restore
    # rewrites the timestamp it was trying to preserve.
    v, s = sh()
    s.run("echo x > /tmp/q")
    m0 = v.nodes["/tmp/q"].mtime
    s.run("touch -a -t 201501010000 /tmp/q")
    a, m, c, _b = clocks(v, "/tmp/q")
    check("touch -a sets atime", int(a), 1420070400)
    check("touch -a leaves mtime", m, m0)
    s.run("touch -m -t 201801010000 /tmp/q")
    a, m, _c, _b = clocks(v, "/tmp/q")
    check("touch -m sets mtime", int(m), 1514764800)
    check("touch -m leaves atime", int(a), 1420070400)

    # touch -r copies each clock from its counterpart.
    v, s = sh()
    s.run("echo x > /tmp/r; echo y > /tmp/t")
    s.run("touch -a -t 201501010000 /tmp/r")
    s.run("touch -m -t 201801010000 /tmp/r")
    s.run("touch -r /tmp/r /tmp/t")
    a, m, _c, _b = clocks(v, "/tmp/t")
    check("touch -r copies atime", int(a), 1420070400)
    check("touch -r copies mtime", int(m), 1514764800)

    # A file touch creates is born now even when -t backdates it.
    v, s = sh()
    s.run("touch -t 202001010000 /tmp/new")
    a, m, c, b = clocks(v, "/tmp/new")
    check("created backdated: mtime is the forgery", int(m), 1577836800)
    check("created backdated: birth is now", abs(b - time.time()) < 5, True)
    check("created backdated: ctime is now", abs(c - time.time()) < 5, True)

    # -- writing and reading ---------------------------------------------
    v, s = sh()
    s.run("echo one > /tmp/w")
    s.run("touch -t 202001010000 /tmp/w")
    time.sleep(0.002)
    s.run("echo two >> /tmp/w")
    a, m, c, _b = clocks(v, "/tmp/w")
    check("append moves mtime", m > 1577836800, True)
    check("append moves ctime", c > 1577836800, True)
    check("append leaves atime", int(a), 1577836800)

    v, s = sh()
    s.run("echo one > /tmp/w")
    s.run("touch -a -t 201501010000 /tmp/w")
    m0 = v.nodes["/tmp/w"].mtime
    s.run("cat /tmp/w")
    a, m, _c, _b = clocks(v, "/tmp/w")
    check("reading moves atime", a > 1420070400, True)
    check("reading leaves mtime", m, m0)
    # relatime: once atime is ahead of mtime it stops moving on every read.
    a1 = v.nodes["/tmp/w"].atime
    time.sleep(0.002)
    s.run("cat /tmp/w")
    check("relatime: the second read does not move it",
          v.nodes["/tmp/w"].atime, a1)

    # -- ls asks for one clock at a time ---------------------------------
    v, s = sh()
    s.run("echo x > /tmp/l")
    s.run("touch -t 202001010000 /tmp/l")
    plain = s.run("ls -l /tmp/l")
    check("ls -l shows the mtime", "2020" in plain, True)
    check("ls -lc shows the ctime", "2020" in s.run("ls -lc /tmp/l"), False)
    check("ls -lu shows the atime", "2020" in s.run("ls -lu /tmp/l"), True)
    check("ls --time=birth shows the birth time",
          "2020" in s.run("ls -l --time=birth /tmp/l"), False)
    check("ls --time=ctime is ls -lc",
          s.run("ls -l --time=ctime /tmp/l"), s.run("ls -lc /tmp/l"))
    check("ls --time=access is ls -lu",
          s.run("ls -l --time=access /tmp/l"), s.run("ls -lu /tmp/l"))

    # -t sorts by whichever clock was selected, which is the whole point of
    # combining them: -lut puts the most recently *read* file first.
    v, s = sh()
    s.run("mkdir -p /tmp/d")
    s.run("echo a > /tmp/d/a; echo b > /tmp/d/b")
    s.run("touch -t 202001010000 /tmp/d/b")     # b is the oldest by mtime
    s.run("cat /tmp/d/b")                        # ...and the newest by atime
    check("ls -t sorts by mtime",
          s.run("ls -t /tmp/d").split(), ["a", "b"])
    check("ls -tu sorts by atime",
          s.run("ls -tu /tmp/d").split(), ["b", "a"])

    # -- find --------------------------------------------------------------
    v, s = sh()
    s.run("mkdir -p /tmp/h && cd /tmp/h && echo a > a && echo b > b")
    s.run("touch -t 202001010000 /tmp/h/a")
    check("-newer compares mtime",
          s.run("cd /tmp/h && find . -maxdepth 1 -type f -newer a").split(),
          ["./b"])
    check("-cnewer compares ctime, so the stomped file is caught",
          sorted(s.run("cd /tmp/h && find . -maxdepth 1 -type f "
                       "-cnewer a").split()), ["./a", "./b"])
    check("-mtime +1 finds the backdated file",
          s.run("cd /tmp/h && find . -maxdepth 1 -type f -mtime +1").split(),
          ["./a"])
    check("-ctime +1 does not -- its ctime is minutes old",
          s.run("cd /tmp/h && find . -maxdepth 1 -type f -ctime +1").split(),
          [])
    check("-ctime -1 finds it",
          sorted(s.run("cd /tmp/h && find . -maxdepth 1 -type f "
                       "-ctime -1").split()), ["./a", "./b"])
    check("-newermt compares mtime against a date",
          s.run("cd /tmp/h && find . -maxdepth 1 -type f "
                "-newermt 2021-01-01").split(), ["./b"])
    check("-newerct is the timestomp sweep",
          sorted(s.run("cd /tmp/h && find . -maxdepth 1 -type f "
                       "-newerct 2021-01-01").split()), ["./a", "./b"])
    check("-anewer compares atime",
          s.run("cd /tmp/h && find . -maxdepth 1 -type f -anewer a").split(),
          ["./b"])
    # -amin/-cmin exist and are minutes, not days.
    check("-cmin -5 finds both",
          sorted(s.run("cd /tmp/h && find . -maxdepth 1 -type f "
                       "-cmin -5").split()), ["./a", "./b"])
    check("-amin -5 does not find the backdated one",
          s.run("cd /tmp/h && find . -maxdepth 1 -type f -amin -5").split(),
          ["./b"])
    # A missing reference is an error, not an empty result.
    s._err = []
    out = s.run("cd /tmp/h && find . -cnewer nosuchfile")
    check("-cnewer with a missing reference fails", out.strip(), "")
    check("...and says so", "nosuchfile" in "".join(s._err), True)

    # -- date ---------------------------------------------------------------
    v, s = sh()
    s.run("echo x > /tmp/dt")
    s.run("touch -t 202001010000 /tmp/dt")
    check("date -r reads the mtime",
          s.run("date -r /tmp/dt +%s").strip(), "1577836800")
    check("date -r agrees with stat",
          s.run("date -r /tmp/dt +%s").strip(),
          s.run("stat -c %Y /tmp/dt").strip())
    check("date -d @0 +%s is 0, not now",
          s.run("date -d @0 +%s").strip(), "0")
    check("date +%s is still now",
          abs(int(s.run("date +%s").strip()) - time.time()) < 5, True)

    # -- copies and links ---------------------------------------------------
    v, s = sh()
    s.run("echo x > /tmp/src")
    s.run("touch -t 202001010000 /tmp/src")
    s.run("cp /tmp/src /tmp/plain")
    s.run("cp -p /tmp/src /tmp/kept")
    check("cp makes a new file with a new mtime",
          v.nodes["/tmp/plain"].mtime > 1577836800, True)
    check("cp -p keeps the mtime",
          int(v.nodes["/tmp/kept"].mtime), 1577836800)
    check("cp -p cannot keep the ctime",
          v.nodes["/tmp/kept"].ctime > 1577836800, True)
    check("cp -p cannot keep the birth time",
          v.nodes["/tmp/kept"].btime > 1577836800, True)

    v, s = sh()
    s.run("echo x > /tmp/ln1")
    s.run("touch -t 202001010000 /tmp/ln1")
    c0 = v.nodes["/tmp/ln1"].ctime
    time.sleep(0.002)
    s.run("ln /tmp/ln1 /tmp/ln2")
    check("hard link moves the inode's ctime",
          v.nodes["/tmp/ln1"].ctime > c0, True)
    check("both names share it",
          v.nodes["/tmp/ln2"].ctime, v.nodes["/tmp/ln1"].ctime)
    check("the mtime is untouched",
          int(v.nodes["/tmp/ln1"].mtime), 1577836800)

    v, s = sh()
    s.run("echo x > /tmp/mv1")
    s.run("touch -t 202001010000 /tmp/mv1")
    c0 = v.nodes["/tmp/mv1"].ctime
    time.sleep(0.002)
    s.run("mv /tmp/mv1 /tmp/mv2")
    check("rename moves ctime", v.nodes["/tmp/mv2"].ctime > c0, True)
    check("rename keeps mtime",
          int(v.nodes["/tmp/mv2"].mtime), 1577836800)

    # -- the forgery survives a reconnect -----------------------------------
    # touch was never journalled, so an attacker who backdated a payload
    # found the original mtime waiting for them on their next login.
    v, s = sh()
    s.run("echo payload > /root/.cache.sh")
    s.run("touch -t 202001010000 /root/.cache.sh")
    saved = v.dump_journal()
    v3 = F.VFS()
    v3.load_journal(saved)
    check("the backdated mtime is journalled",
          int(v3.nodes["/root/.cache.sh"].mtime), 1577836800)
    check("and its ctime is still not backdated",
          v3.nodes["/root/.cache.sh"].ctime > 1577836800, True)

    for label, got, want in FAILS:
        print("FAIL %s\n  got  %r\n  want %r" % (label, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("stamptest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
