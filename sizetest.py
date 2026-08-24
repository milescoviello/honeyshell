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

    for label, got, want in FAILS:
        print("FAIL %s\n  got  %r\n  want %r" % (label, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("sizetest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
