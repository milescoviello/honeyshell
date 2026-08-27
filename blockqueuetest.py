"""/sys/block/*/queue, and the five lsblk columns that read it.

Carried over as a noted-but-unfixed item from an earlier sweep: queue held
three files against the guest's 44. It turned out to be the same bug seen
from two directions.

    ours   guest
      3      44     /sys/block/sda/queue
      3      44     /sys/block/sr0/queue
     30      31     /sys/block/sda            (the parent was nearly right)

From the other side, asking lsblk for the columns those files back:

    $ lsblk -dno NAME,ROTA,RO,RM,SIZE,TYPE,PHY-SEC,LOG-SEC,SCHED,DISC-GRAN
    guest      sda 1 0 0   64G disk     512     512 none     4K
    ours       sda   0 0   64G disk
                 ^                  ^^^^^^^^^^^^^^^^^^^^^^^^^^^
    five empty columns

The rows lsblk prints were a hardcoded table with no ROTA, PHY-SEC,
LOG-SEC, SCHED or DISC-GRAN key in them at all, so those columns could
only ever be blank -- while /sys/block/<dev>/queue is exactly where a real
lsblk reads them from. Filling the directory and having lsblk read it
fixes both ends and stops them drifting apart again.

Values are per device: 16 of the 44 keys differ between sda and sr0, so
one table for both would have given the CD-ROM a hard drive's geometry.
The one that shows is the sector size -- a CD is 2048 and ours said 512,
which lsblk then printed as LOG-SEC.

rotational and scheduler keep the values the persona already set; the rest
came off the guest.

Usage:  python3 blockqueuetest.py
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


def shell():
    fs = fakeshell.VFS()
    return fakeshell.Shell(vfs=fs, peer="198.51.100.15", peer_port=40444)


sh = shell()


def r(cmd):
    try:
        return sh.run(cmd).rstrip("\n")
    except Exception as exc:                                   # noqa: BLE001
        return "<raised %s: %s>" % (type(exc).__name__, exc)


def q(dev, key):
    return r("cat /sys/block/%s/queue/%s 2>/dev/null" % (dev, key))


def col(dev, name):
    """One lsblk column for one device, or "" when it prints nothing."""
    for line in r("lsblk -dno NAME,%s" % name).splitlines():
        f = line.split()
        if f and f[0] == dev:
            return f[1] if len(f) > 1 else ""
    return "<no row>"


# ------------------------------------------------------------ the breadth
for dev in ("sda", "sr0"):
    n = r("ls /sys/block/%s/queue 2>/dev/null | wc -l" % dev)
    try:
        n = int(n)
    except ValueError:
        n = -1
    check("/sys/block/%s/queue is a real directory" % dev, n >= 40, True,
          "the guest has 44, we had 3; got %d" % n)

# -------------------------------------------- the keys anything reads
for dev in ("sda", "sr0"):
    for key in ("rotational", "logical_block_size", "physical_block_size",
                "scheduler", "discard_granularity", "nr_requests",
                "read_ahead_kb", "max_sectors_kb", "write_cache"):
        check("%s/queue/%s is readable" % (dev, key),
              bool(q(dev, key)) and "No such file" not in q(dev, key), True,
              "got %r" % q(dev, key))

# ------------------------------------- a CD-ROM is not a hard drive
check("sr0 has a CD-ROM's sector size", q("sr0", "logical_block_size"),
      "2048", "16 of the 44 keys differ between the two devices; copying "
              "sda's table to both is how this became 512")
check("...and sda has a disk's", q("sda", "logical_block_size"), "512")
check("sr0 is removable in every reader",
      (q("sr0", "rotational"), col("sr0", "RM")), ("1", "1"))

# ----------------------------------------- lsblk reads what /sys holds
for dev in ("sda", "sr0"):
    check("lsblk ROTA for %s comes from queue/rotational" % dev,
          col(dev, "ROTA"), q(dev, "rotational"),
          "this column was empty while the file had the answer")
    check("lsblk LOG-SEC for %s matches" % dev,
          col(dev, "LOG-SEC"), q(dev, "logical_block_size"))
    check("lsblk PHY-SEC for %s matches" % dev,
          col(dev, "PHY-SEC"), q(dev, "physical_block_size"))

check("lsblk SCHED prints the active scheduler, not the list",
      col("sda", "SCHED"), "none",
      "the file holds '[none] mq-deadline' and lsblk prints the bracketed "
      "one; got %r" % q("sda", "scheduler"))
check("lsblk DISC-GRAN is a human size",
      col("sda", "DISC-GRAN"), "4K",
      "discard_granularity is %r bytes, and _df_human takes kilobytes -- "
      "feeding it 512-byte blocks printed 8K"
      % q("sda", "discard_granularity"))
check("...and zero prints as 0B", col("sr0", "DISC-GRAN"), "0B")

# ------------------------------------- none of them is blank any more
line = r("lsblk -dno NAME,ROTA,RO,RM,SIZE,TYPE,PHY-SEC,LOG-SEC,SCHED,"
         "DISC-GRAN")
first = [l for l in line.splitlines() if l.startswith("sda")]
check("every requested column is populated",
      len(first[0].split()) if first else 0, 10,
      "five of the ten were empty; got %r" % (first[0] if first else line))

# --------------------------------------- and the default output is intact
plain = r("lsblk")
check("the default tree still has its partitions",
      all(p in plain for p in ("sda1", "sda14", "sda15", "sr0")), True)
check("...and still its header", plain.splitlines()[0].split()[0], "NAME")

# ------------------------------------------ the numbers line up as lsblk's
head = r("lsblk -do NAME,ROTA,PHY-SEC,LOG-SEC,SCHED,DISC-GRAN")
rows = head.splitlines()
check("a headed listing right-aligns its numbers",
      rows[1].split()[1:4] if len(rows) > 1 else [],
      [q("sda", "rotational"), q("sda", "physical_block_size"),
       q("sda", "logical_block_size")])
check("...under a header of the right width",
      rows[0].split() if rows else [],
      ["NAME", "ROTA", "PHY-SEC", "LOG-SEC", "SCHED", "DISC-GRAN"])

for f in FAILS:
    print(" ", f)
print("   blockqueue: %d checks, %d differ" % (len(CHECKS), len(FAILS)))
sys.exit(1 if FAILS else 0)
