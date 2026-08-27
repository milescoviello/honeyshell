"""How much of /proc/sys is here, and does one knob answer to one value?

Two findings from one axis, both reached by counting rather than guessing.

## The tree was 15% of a real one

    tree        ours   guest
    kernel        24     124
    vm            12      52
    fs            10      29
    net/ipv4      11     144
    net/core       3      42
    TOTAL         60     391

A sysctl key that does not exist is not a wrong value, it is a missing
file: `sysctl -n kernel.core_uses_pid` answered "cannot stat
/proc/sys/kernel/core_uses_pid: No such file or directory" for a key every
Linux box has. Anything enumerating the tree, and any tuning script that
reads before it writes, sees that at once -- and a miner tuning the box is
exactly the visitor we get. 203.0.113.33 set vm.nr_hugepages here before
unpacking SRBMiner.

Every name and value was read off the guest. The fill is purely additive:
the keys already modelled are left alone, because several are *live* --
nr_hugepages drives /proc/meminfo, kernel.hostname moves when `hostname`
runs -- and a static seed would freeze them.

## And ip_forward disagreed with itself

net.ipv4.ip_forward and net.ipv4.conf.all.forwarding are the same kernel
value. Ours were separate files:

    sysctl -w net.ipv4.ip_forward=1
    cat /proc/sys/net/ipv4/conf/all/forwarding    ->  0

The box disagreeing with itself about whether it routes, which is the
first thing anyone pivoting checks. Measured on the guest inside
`unshare --net --mount`, so its own ip_forward -- which the isolation gate
depends on -- was never touched:

    before                  ip_forward=0 all=0 lo=0
    set ip_forward=1     -> ip_forward=1 all=1 lo=1
    set all/forwarding=0 -> ip_forward=0 all=0

Bidirectional, and it reaches every interface.

Usage:  python3 sysctlbreadthtest.py
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


def count(d):
    out = r("ls /proc/sys/%s 2>/dev/null | wc -l" % d)
    try:
        return int(out.strip())
    except ValueError:
        return -1


# ------------------------------------------------------------- the breadth
# Counts measured on the guest. Held as a floor rather than an equality:
# the point is that the tree is a real tree, and a kernel upgrade there
# would move these by a key or two without anything here being wrong.
for tree, want in (("kernel", 124), ("vm", 52), ("fs", 29),
                   ("net/ipv4", 144), ("net/core", 42)):
    got = count(tree)
    check("/proc/sys/%s is a real tree" % tree, got >= want - 2, True,
          "guest has %d, we have %d" % (want, got))

check("the whole tree is not a stub",
      sum(count(d) for d in ("kernel", "vm", "fs", "net/ipv4", "net/core"))
      >= 380, True,
      "60 against the guest's 391 was the finding")

# --------------------------------------------- the key that started it
check("kernel.core_uses_pid exists at all",
      r("sysctl -n kernel.core_uses_pid"), "1",
      "this answered 'cannot stat ... No such file or directory'")
check("...and /proc agrees with sysctl",
      r("cat /proc/sys/kernel/core_uses_pid"),
      r("sysctl -n kernel.core_uses_pid"))

# ----------------------------------- keys a loader or a miner reads
for key, want in (("vm.swappiness", "60"),
                  ("net.ipv4.tcp_congestion_control", "cubic"),
                  ("kernel.io_uring_disabled", "0"),
                  ("net.core.somaxconn", "4096")):
    check("%s is answered" % key, r("sysctl -n %s" % key), want,
          "measured on the guest")
check("kernel.seccomp.actions_avail is there",
      "kill_process" in r("sysctl -n kernel.seccomp.actions_avail"), True,
      "an exploit reads this before deciding what to try")
check("the subdirectories exist too",
      all(r("test -d /proc/sys/%s && echo y || echo n" % d) == "y"
          for d in ("kernel/keys", "kernel/seccomp", "fs/quota",
                    "net/ipv4/neigh/default")), True)

# ------------------------------ per-interface trees mirror this box's links
links = sorted(r("ls /sys/class/net").split())
for d in ("net/ipv4/conf", "net/ipv4/neigh"):
    have = sorted(x for x in r("ls /proc/sys/%s" % d).split()
                  if x not in ("all", "default"))
    check("%s covers this box's interfaces" % d, have, links,
          "a per-interface directory for an interface that does not exist "
          "here would be its own contradiction")

# -------------------------------------------- the live keys stayed live
check("kernel.hostname still tracks the hostname",
      (r("hostname box2"), r("sysctl -n kernel.hostname"))[1], "box2",
      "the fill must not have frozen a key that moves")
r("hostname web01")
r("sysctl -w vm.nr_hugepages=4 >/dev/null 2>&1")
check("vm.nr_hugepages still drives /proc/meminfo",
      "4" in r("grep HugePages_Total /proc/meminfo"), True)
r("sysctl -w vm.nr_hugepages=0 >/dev/null 2>&1")

# ------------------------------------------------- one knob, one value
def fwd():
    return (r("cat /proc/sys/net/ipv4/ip_forward"),
            r("cat /proc/sys/net/ipv4/conf/all/forwarding"),
            r("cat /proc/sys/net/ipv4/conf/lo/forwarding"),
            r("cat /proc/sys/net/ipv4/conf/eth0/forwarding"))


check("forwarding starts off everywhere", fwd(), ("0", "0", "0", "0"))
r("sysctl -w net.ipv4.ip_forward=1")
check("setting ip_forward sets conf/all/forwarding", fwd(),
      ("1", "1", "1", "1"),
      "one kernel value under several names; this left all=0")
r("echo 0 > /proc/sys/net/ipv4/conf/all/forwarding")
check("...and clearing conf/all clears ip_forward", fwd(),
      ("0", "0", "0", "0"), "the link is bidirectional on a real kernel")
r("sysctl -w net.ipv4.conf.all.forwarding=1")
check("...whichever name is used", fwd(), ("1", "1", "1", "1"))
check("sysctl and the file agree afterwards",
      r("sysctl -n net.ipv4.ip_forward"),
      r("cat /proc/sys/net/ipv4/ip_forward"))
r("sysctl -w net.ipv4.ip_forward=0")

# a value with trailing junk must not become the value verbatim
r("sysctl -w net.ipv4.ip_forward=1")
check("a set survives a read-back as a bare digit",
      r("cat /proc/sys/net/ipv4/conf/eth0/forwarding"), "1")
r("sysctl -w net.ipv4.ip_forward=0")

for f in FAILS:
    print(" ", f)
print("   sysctlbreadth: %d checks, %d differ" % (len(CHECKS), len(FAILS)))
sys.exit(1 if FAILS else 0)
