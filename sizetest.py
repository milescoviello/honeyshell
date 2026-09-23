#!/usr/bin/env python3
"""How big is this file, and what did it cost the disk?

Those are two questions and the box answered both with one number. A
file's apparent size and its allocation are independent: `truncate -s 2G
img` makes a two-gigabyte file that occupies nothing, `fallocate -n -l
50M img` occupies fifty megabytes while staying zero bytes long. With one
size, a hole and real data were indistinguishable -- and every reader
disagreed anyway, because df counted stored bytes while ls, du and stat
counted the size the inode claims. On one 2 GiB file:

    ls -l   2147483648      du      2097152 (should be 0)
    stat %s 2147483648      stat %b 4194304 (should be 0)
    df      unchanged       wc -c   33554432

Six readers, four answers. A dropper checks free space before it fetches
and the size after; RedTail's setup.sh picks its install directory that
way.

That pass unified du, ls -s and `stat -c %b` for regular files and
stopped there. Three classes of inode were never routed through the shared
helper, and find was never routed through it at all:

  * **symlinks.** ext4 stores a target of up to 59 bytes inside the inode
    and allocates nothing; 60 bytes and over gets a block. We charged
    every symlink a full block in stat and du while ls -s charged none,
    so `stat -c %b`, `du` and `ls -s` said 8, 4 and 0 for the same link.
    Measured across a 10..300 byte ladder on the guest: L59 is 0 and L60
    is 8.
  * **/proc and /sys.** du carried its own rule for them and ls -s
    carried another; `stat -c %b` carried none, so it was the only reader
    on the box that said a sysfs attribute occupies eight blocks where
    the guest says zero.
  * **find -size -N.** find rounds the file up to whole units and then
    compares, for every form. -N was a raw byte comparison, so
    `find / -size -1M` matched every file under a megabyte where find
    matches only an empty one -- 292584 bytes is one unit rounded up, and
    one is not less than one. The + and bare forms happened to agree
    already, because ceil(s/u) > n is the same statement as s > n*u.
  * **find -printf %b, %k and %S.** Not directives at all, so
    `find -printf "%s %k"` printed the size and then the two characters
    "%k" back at the caller.

Reference behaviour measured on the guest (Debian 13, ext4).
"""
import sys
import fakeshell as F

FAILS, CHECKS = [], []


def check(label, got, want):
    CHECKS.append(label)
    if got != want:
        FAILS.append((label, got, want))


def sh():
    v = F.VFS()
    s = F.Shell(v, peer="203.0.113.44")
    s.exec_mode = True
    return v, s


def used(s):
    return int(s.run("df --output=used / | tail -1").strip())


def field(s, path, spec):
    return s.run("stat -c '%s' %s" % (spec, path)).strip()


def main():
    # -- truncate digs a hole ---------------------------------------------
    v, s = sh()
    before = used(s)
    s.run("truncate -s 2G /root/t.img")
    check("truncate: ls -l reports the full size",
          s.run("ls -l /root/t.img").split()[4], "2147483648")
    check("truncate: stat %s agrees", field(s, "/root/t.img", "%s"),
          "2147483648")
    check("truncate: stat %b is zero -- it is a hole",
          field(s, "/root/t.img", "%b"), "0")
    check("truncate: du reports nothing",
          s.run("du -sk /root/t.img").split()[0], "0")
    check("truncate: du --apparent-size reports the size",
          s.run("du --apparent-size -sk /root/t.img").split()[0], "2097152")
    check("truncate: wc -c agrees with ls",
          s.run("wc -c /root/t.img").split()[0], "2147483648")
    check("truncate: df does not move", used(s), before)

    # The size operand is not a file. `truncate -s 2G f` used to create a
    # file called 2G beside f, and charge the disk for both.
    check("no stray file named after the size",
          sorted(s.run("ls /root").split()),
          ["backup.sql", "deploy.log", "scripts", "t.img"])

    # -- fallocate reserves blocks ----------------------------------------
    v, s = sh()
    before = used(s)
    s.run("fallocate -l 200M /root/f.img")
    check("fallocate: size", field(s, "/root/f.img", "%s"), "209715200")
    check("fallocate: blocks are real", field(s, "/root/f.img", "%b"),
          "409600")
    check("fallocate: du charges for it",
          s.run("du -sk /root/f.img").split()[0], "204800")
    check("fallocate: df moves by the same amount",
          used(s) - before, 204800)
    check("no stray file named after the length",
          "200M" in s.run("ls /root").split(), False)

    # -n reserves without changing the length, which is the one shape a
    # single size could not express.
    v, s = sh()
    s.run("touch /root/n.img && fallocate -n -l 50M /root/n.img")
    check("fallocate -n: size stays zero", field(s, "/root/n.img", "%s"), "0")
    check("fallocate -n: blocks are reserved anyway",
          s.run("du -sk /root/n.img").split()[0], "51200")

    # -- dd honours count --------------------------------------------------
    v, s = sh()
    before = used(s)
    out = s.run("dd if=/dev/zero of=/root/d.img bs=1M count=200 2>&1")
    check("dd reports the full byte count",
          "209715200 bytes (210 MB, 200 MiB) copied" in out, True)
    check("dd: the file is that big", field(s, "/root/d.img", "%s"),
          "209715200")
    check("dd: du agrees", s.run("du -sk /root/d.img").split()[0], "204800")
    check("dd: df agrees", used(s) - before, 204800)
    check("dd: records out", "200+0 records out" in out, True)
    # The elapsed time and the rate have to divide out to each other.
    tail = [x.strip() for x in out.strip().splitlines()[-1].split(",")]
    secs = float(tail[1].split()[0])
    rate = float(tail[2].split()[0])
    check("dd: time and rate are consistent",
          abs(209715200 / secs / 1e9 - rate) < 0.1, True)
    # GNU prints three significant digits, so 209715200 is "210 MB".
    check("dd: a small copy still reads right",
          "1048576 bytes (1.0 MB, 1.0 MiB) copied"
          in s.run("dd if=/dev/zero of=/root/s.img bs=1M count=1 2>&1"), True)

    # -- deleting gives the space back -------------------------------------
    v, s = sh()
    before = used(s)
    s.run("fallocate -l 300M /root/big")
    grew = used(s)
    s.run("rm /root/big")
    check("df grew", grew - before, 307200)
    check("df gave it back", used(s), before)

    # -- truncate's relative forms -----------------------------------------
    v, s = sh()
    s.run("truncate -s 100 /tmp/r")
    for spec, want in (("+50", "150"), ("-20", "130"), (">1000", "1000"),
                       ("<500", "500"), ("%256", "512"), ("/100", "500")):
        s.run("truncate -s '%s' /tmp/r" % spec)
        check("truncate -s %s" % spec, field(s, "/tmp/r", "%s"), want)
    # A relative form that used to silently truncate to zero.
    v, s = sh()
    s.run("echo -n 0123456789 > /tmp/g")
    s.run("truncate -s +10M /tmp/g")
    check("truncate -s +10M grows, not zeroes",
          field(s, "/tmp/g", "%s"), str(10 * 1024 * 1024 + 10))
    # -r takes the size from another file.
    s.run("truncate -s 4096 /tmp/ref")
    s.run("truncate -r /tmp/ref /tmp/g")
    check("truncate -r copies the reference size",
          field(s, "/tmp/g", "%s"), "4096")
    # -c does not create.
    s.run("truncate -c -s 10 /tmp/never")
    check("truncate -c does not create", s.run("ls /tmp/never 2>/dev/null"),
          "")
    # ...and without -c it does.
    s.run("truncate -s 10 /tmp/made")
    check("truncate creates otherwise", field(s, "/tmp/made", "%s"), "10")

    # Errors, so a script that gets them wrong sees the same thing it would.
    v, s = sh()
    s._err = []
    _o, rc = s.dispatch("truncate", ["/tmp/x"], "")
    check("truncate with no size fails", rc, 1)
    check("...and says which option", "--size" in "".join(s._err), True)
    s._err = []
    _o, rc = s.dispatch("fallocate", ["/tmp/x"], "")
    check("fallocate with no length fails", rc, 1)
    check("...and says so", "length" in "".join(s._err), True)

    # -- the readers agree on an ordinary file too --------------------------
    v, s = sh()
    s.run("head -c 100000 /dev/zero > /tmp/h")
    size = field(s, "/tmp/h", "%s")
    check("ls and stat agree", s.run("ls -l /tmp/h").split()[4], size)
    check("wc -c agrees", s.run("wc -c /tmp/h").split()[0], size)
    check("du charges the rounded-up allocation",
          s.run("du -sk /tmp/h").split()[0],
          str(((int(size) + 4095) // 4096) * 4))

    # A stock binary's bytes are synthesised, and it used to cost the disk
    # nothing at all -- 4.1G of Debian occupying zero blocks.
    v, s = sh()
    n = v.nodes["/usr/bin/ls"]
    check("a stock binary has a size", F.node_size(n, "/usr/bin/ls") > 10000,
          True)
    check("and it is charged for it",
          F.node_alloc(n, "/usr/bin/ls"), F.node_size(n, "/usr/bin/ls"))

    # -- the size survives a reconnect --------------------------------------
    v, s = sh()
    s.run("fallocate -l 100M /root/keep.img")
    v2 = F.VFS()
    v2.load_journal(v.dump_journal())
    n = v2.nodes.get("/root/keep.img")
    check("the allocation is journalled", n is not None
          and F.node_size(n, "/root/keep.img") == 104857600, True)

    # -- a symlink's target lives in the inode until it does not ----------
    v, s = sh()
    s.run("mkdir -p /tmp/lt")
    for n in (10, 40, 59, 60, 61, 100, 300):
        s.run("ln -s %s /tmp/lt/L%d" % ("a" * n, n))
    for n, blocks in ((10, "0"), (40, "0"), (59, "0"),
                      (60, "8"), (61, "8"), (100, "8"), (300, "8")):
        p = "/tmp/lt/L%d" % n
        kb = "0" if blocks == "0" else "4"
        check("L%d: stat %%s is the target length" % n, field(s, p, "%s"),
              str(n))
        check("L%d: stat %%b" % n, field(s, p, "%b"), blocks)
        check("L%d: du agrees with stat" % n,
              s.run("du %s" % p).split()[0], kb)
        check("L%d: ls -s agrees with both" % n,
              s.run("ls -s %s" % p).split()[0], kb)

    # -- neither pseudo filesystem charges for anything --------------------
    v, s = sh()
    for p in ("/proc/meminfo", "/proc/self/fd/0",
              "/sys/class/net/eth0/address", "/sys/class/net", "/dev/null"):
        check("%s: stat %%b" % p, field(s, p, "%b"), "0")
        check("%s: du" % p, s.run("du %s" % p).split()[0], "0")
        # -d, because two of these are directories and `ls -s` on one
        # lists what is inside it.
        check("%s: ls -sd" % p, s.run("ls -sd %s" % p).split()[0], "0")
    out = s.run("ls -s /proc/1")
    check("ls -s /proc/1 totals zero", out.splitlines()[0], "total 0")
    check("and every cell in it is zero",
          sorted(set(l.split()[0] for l in out.splitlines()[1:] if l.split())),
          ["0"])

    # -- find rounds up, for every form ------------------------------------
    v, s = sh()
    s.run("mkdir -p /tmp/sq")
    SIZES = (0, 1, 512, 513, 1024, 1025, 1500, 2048, 4096, 4097, 500000,
             1048576)
    for n in SIZES:
        s.run("head -c %d /dev/zero > /tmp/sq/f%d" % (n, n))

    def matched(q):
        got = s.run("cd /tmp/sq && find . -maxdepth 1 -type f -size %s "
                    "-printf '%%f\n'" % q)
        return sorted(got.split())

    def want(q):
        import re as _re
        m = _re.match(r"([+-]?)(\d+)([bcwkMG]?)", q)
        unit = {"b": 512, "": 512, "c": 1, "w": 2, "k": 1024,
                "M": 1 << 20, "G": 1 << 30}[m.group(3)]
        n = int(m.group(2))
        out = []
        for sz in SIZES:
            blocks = (sz + unit - 1) // unit
            ok = (blocks > n if m.group(1) == "+" else
                  blocks < n if m.group(1) == "-" else blocks == n)
            if ok:
                out.append("f%d" % sz)
        return sorted(out)

    # Every one of these was compared against the guest, file for file.
    for q in ("0", "1", "2", "1k", "-2k", "+1k", "-1M", "+0", "-1", "+1",
              "1c", "-100c", "+512c", "-1500c", "2b", "-2b", "+1b", "-3",
              "+2k", "1M", "-2M"):
        check("find -size %s" % q, matched(q), want(q))

    # The shape that made this visible: an apparently-small log file.
    check("find -size -1M does not match a 292KB file",
          s.run("find /var/log/lastlog -size -1M -printf SMALL"), "")
    check("find -size 1M does",
          s.run("find /var/log/lastlog -size 1M -printf ONE"), "ONE")

    # -- find prints the same numbers as du, ls -s and stat ----------------
    v, s = sh()
    s.run("head -c 4097 /dev/zero > /tmp/p4097")
    s.run(": > /tmp/pempty")
    s.run("ln -s %s /tmp/plong" % ("a" * 100))
    for path, want_str in (("/tmp/p4097", "4097|16|8|1.99951"),
                           ("/tmp/pempty", "0|0|0|1"),
                           ("/etc", "4096|8|4|1"),
                           ("/etc/hostname", "6|8|4|682.667"),
                           ("/tmp/plong", "100|8|4|40.96")):
        check("find -printf %%s|%%b|%%k|%%S %s" % path,
              s.run("find %s -maxdepth 0 -printf '%%s|%%b|%%k|%%S'" % path),
              want_str)
    check("find %b is stat -c %b",
          s.run("find /tmp/p4097 -printf '%b'"), field(s, "/tmp/p4097", "%b"))
    check("find %k is du",
          s.run("find /tmp/p4097 -printf '%k'"),
          s.run("du /tmp/p4097").split()[0])

    for label, got, want in FAILS:
        print("FAIL %s\n  got  %r\n  want %r" % (label, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("sizetest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
