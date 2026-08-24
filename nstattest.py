#!/usr/bin/env python3
"""How much traffic has this box seen, and who is counting?

Four commands read one set of kernel counters -- /proc/net/dev,
`ip -s link`, `ifconfig`, and the files under
/sys/class/net/<if>/statistics/ -- and there were two sets behind them.
The first three grew with uptime; sysfs was eight files seeded once with
literals and never touched again:

    cat /sys/class/net/eth0/statistics/rx_bytes      148223991
    ip -s link show eth0        RX bytes            2379742622

The same counter, sixteen times apart, from two commands anyone profiling
a host runs. Monitoring agents read sysfs; people read ip.

The multicast column had a third answer of its own: /proc/net/dev printed
1204 and `ip -s link` printed 118, both literals, for one interface.

The statistics directory held eight files where the kernel exports
twenty-four -- no multicast, no collisions, none of the error breakdown --
and the interface's own attribute set held ten of the guest's thirty-eight,
missing speed and duplex, which are the first two things a profiler reads.
virtio answers -1 and unknown there; that is not the same as the file not
being there.

And `ip -s -s link` printed exactly what `ip -s link` printed: the second
-s was folded into the same boolean, so the flag whose whole job is to show
the error breakdown showed nothing extra.

Column positions and attribute values measured on the guest.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = 0, 0
FAILURES = []

# The counters move with uptime, so two commands a moment apart legitimately
# differ. eth0 grows by 594 bytes a second here; a second of slack is plenty
# and still catches a reader that is off by a factor of sixteen.
SLACK = 4000


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
    else:
        FAIL += 1
        FAILURES.append("%-58s %s" % (name, detail))


S = fs.Shell(fs.VFS())
S.exec_mode = True


def R(cmd):
    S._err = []
    out = S.run(cmd)
    return out or "", "".join(S._err), S.last_rc


def procdev(iface):
    for line in R("cat /proc/net/dev")[0].splitlines():
        f = line.replace(":", " ").split()
        if f and f[0] == iface:
            return {"rx_bytes": int(f[1]), "rx_packets": int(f[2]),
                    "rx_errors": int(f[3]), "rx_dropped": int(f[4]),
                    "multicast": int(f[8]), "tx_bytes": int(f[9]),
                    "tx_packets": int(f[10])}
    return {}


def iplink(iface, extra=False):
    out = R("ip -s %slink show %s" % ("-s " if extra else "", iface))[0]
    m = re.search(r"RX: bytes.*\n\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)"
                  r"\s+(\d+)", out)
    t = re.search(r"TX: bytes.*\n\s*(\d+)\s+(\d+)", out)
    if not m or not t:
        return {}
    return {"rx_bytes": int(m.group(1)), "rx_packets": int(m.group(2)),
            "rx_errors": int(m.group(3)), "rx_dropped": int(m.group(4)),
            "multicast": int(m.group(6)), "tx_bytes": int(t.group(1)),
            "tx_packets": int(t.group(2))}


def sysfs(iface):
    out = {}
    for k in ("rx_bytes", "rx_packets", "rx_errors", "rx_dropped",
              "multicast", "tx_bytes", "tx_packets"):
        v = R("cat /sys/class/net/%s/statistics/%s" % (iface, k))[0].strip()
        out[k] = int(v) if v.lstrip("-").isdigit() else None
    return out


def near(a, b):
    return a is not None and b is not None and abs(a - b) <= SLACK


# ---------------------------------------------------------------------------
# One counter, four readers
# ---------------------------------------------------------------------------
def t_the_four_readers_agree():
    for iface in ("eth0", "lo"):
        p, i, y = procdev(iface), iplink(iface), sysfs(iface)
        check("%s: /proc/net/dev has a row" % iface, bool(p), "missing")
        check("%s: ip -s link has counters" % iface, bool(i), "missing")
        if not (p and i):
            continue
        for k in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets"):
            check("%s: sysfs %s agrees with /proc/net/dev" % (iface, k),
                  near(y[k], p[k]), "sysfs %s, procdev %s" % (y[k], p[k]))
            check("%s: ip -s link %s agrees with /proc/net/dev" % (iface, k),
                  near(i[k], p[k]), "ip %s, procdev %s" % (i[k], p[k]))
        # The counters that do not move must be equal, not merely close.
        check("%s: multicast is one number" % iface,
              p["multicast"] == i["multicast"] == y["multicast"],
              "procdev %s, ip %s, sysfs %s"
              % (p["multicast"], i["multicast"], y["multicast"]))
        for k in ("rx_errors", "rx_dropped"):
            check("%s: %s is one number" % (iface, k),
                  p[k] == i[k] == y[k],
                  "procdev %s, ip %s, sysfs %s" % (p[k], i[k], y[k]))


def t_ifconfig_reads_the_same_counters():
    out = R("ifconfig eth0")[0]
    m = re.search(r"RX packets (\d+)\s+bytes (\d+)", out)
    t = re.search(r"TX packets (\d+)\s+bytes (\d+)", out)
    check("ifconfig prints RX and TX lines", m and t, out[:70])
    if not (m and t):
        return
    p = procdev("eth0")
    check("ifconfig's RX bytes is /proc/net/dev's",
          near(int(m.group(2)), p["rx_bytes"]),
          "%s vs %s" % (m.group(2), p["rx_bytes"]))
    check("ifconfig's TX bytes is /proc/net/dev's",
          near(int(t.group(2)), p["tx_bytes"]),
          "%s vs %s" % (t.group(2), p["tx_bytes"]))
    check("and the packet counts too",
          near(int(m.group(1)), p["rx_packets"])
          and near(int(t.group(1)), p["tx_packets"]),
          "%s/%s vs %s/%s" % (m.group(1), t.group(1),
                              p["rx_packets"], p["tx_packets"]))
    # net-tools has to be a package the box admits to having.
    check("dpkg owns the ifconfig that answered",
          "net-tools" in R("dpkg -S %s" % R("which ifconfig")[0].strip())[0],
          R("dpkg -S /usr/sbin/ifconfig")[0][:50])


def t_counters_only_go_up():
    a = procdev("eth0")
    R("sleep 0")
    b = procdev("eth0")
    for k in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets"):
        check("eth0 %s never goes backwards" % k, b[k] >= a[k],
              "%s then %s" % (a[k], b[k]))


# ---------------------------------------------------------------------------
# The statistics directory the kernel actually exports
# ---------------------------------------------------------------------------
GUEST_STATS = ("collisions", "multicast", "rx_bytes", "rx_compressed",
               "rx_crc_errors", "rx_dropped", "rx_errors", "rx_fifo_errors",
               "rx_frame_errors", "rx_length_errors", "rx_missed_errors",
               "rx_nohandler", "rx_over_errors", "rx_packets",
               "tx_aborted_errors", "tx_bytes", "tx_carrier_errors",
               "tx_compressed", "tx_dropped", "tx_errors", "tx_fifo_errors",
               "tx_heartbeat_errors", "tx_packets", "tx_window_errors")


def t_the_statistics_directory_is_complete():
    for iface in ("eth0", "lo"):
        have = R("ls /sys/class/net/%s/statistics/" % iface)[0].split()
        check("%s: all twenty-four counter files" % iface,
              sorted(have) == sorted(GUEST_STATS),
              str(sorted(set(GUEST_STATS) - set(have))[:4]))
        bad = []
        for name in have:
            v = R("cat /sys/class/net/%s/statistics/%s"
                  % (iface, name))[0].strip()
            if not v.isdigit():
                bad.append("%s=%r" % (name, v))
        check("%s: every counter file holds a number" % iface, not bad,
              str(bad[:3]))


def t_the_interface_attributes_are_there():
    have = set(R("ls /sys/class/net/eth0/")[0].split())
    for name in ("address", "broadcast", "carrier", "carrier_changes",
                 "dev_id", "duplex", "flags", "ifindex", "iflink",
                 "link_mode", "mtu", "operstate", "speed", "statistics",
                 "tx_queue_len", "type", "uevent"):
        check("eth0 exports %s" % name, name in have,
              str(sorted(have)[:5]))
    # virtio has no link speed, and says so rather than being absent.
    check("speed is virtio's -1", R("cat /sys/class/net/eth0/speed")[0].strip()
          == "-1", R("cat /sys/class/net/eth0/speed")[0].strip())
    check("duplex is unknown",
          R("cat /sys/class/net/eth0/duplex")[0].strip() == "unknown",
          R("cat /sys/class/net/eth0/duplex")[0].strip())


def t_sysfs_attributes_match_ip_link():
    link = R("ip link show eth0")[0]
    m = re.match(r"(\d+): eth0: <([^>]*)> mtu (\d+) .* qlen (\d+)", link)
    check("ip link show eth0 parsed", m is not None, link[:60])
    if not m:
        return
    idx, _flags, mtu, qlen = m.groups()
    def sf(name):
        return R("cat /sys/class/net/eth0/%s" % name)[0].strip()
    check("ifindex agrees with ip's index", sf("ifindex") == idx,
          "%s vs %s" % (sf("ifindex"), idx))
    check("mtu agrees", sf("mtu") == mtu, "%s vs %s" % (sf("mtu"), mtu))
    check("tx_queue_len agrees with qlen", sf("tx_queue_len") == qlen,
          "%s vs %s" % (sf("tx_queue_len"), qlen))
    mac = re.search(r"link/ether (\S+)", link).group(1)
    check("address agrees with link/ether", sf("address") == mac,
          "%s vs %s" % (sf("address"), mac))
    brd = re.search(r"brd (\S+)", link).group(1)
    check("broadcast agrees with brd", sf("broadcast") == brd,
          "%s vs %s" % (sf("broadcast"), brd))
    check("operstate agrees with state UP", sf("operstate") == "up"
          and " state UP " in link, sf("operstate"))
    check("carrier is 1 while LOWER_UP is set",
          sf("carrier") == "1" and "LOWER_UP" in link, sf("carrier"))
    check("loopback's type is 772", R("cat /sys/class/net/lo/type")[0].strip()
          == "772", R("cat /sys/class/net/lo/type")[0].strip())
    check("ethernet's type is 1", sf("type") == "1", sf("type"))
    # ...and the directory lists exactly the interfaces ip does.
    names = set(R("ls /sys/class/net/")[0].split())
    ipnames = set(re.findall(r"^\d+: (\S+?):", R("ip link")[0], re.M))
    check("sysfs and ip list the same interfaces", names == ipnames,
          "%s vs %s" % (sorted(names), sorted(ipnames)))


# ---------------------------------------------------------------------------
# -s -s is a second level of detail
# ---------------------------------------------------------------------------
def t_double_s_adds_the_error_breakdown():
    one = R("ip -s link show eth0")[0]
    two = R("ip -s -s link show eth0")[0]
    check("ip -s link has no error breakdown", "RX errors:" not in one,
          one[-60:])
    check("ip -s -s link does", "RX errors:" in two and "TX errors:" in two,
          two[-60:])
    # Two blocks, each a header and a value row: four lines, not two.
    check("and it is four lines longer than the single form",
          len(two.splitlines()) == len(one.splitlines()) + 4,
          "%d vs %d" % (len(two.splitlines()), len(one.splitlines())))
    # The columns line up with their own headers, as on the guest.
    lines = two.splitlines()
    for i, l in enumerate(lines):
        if l.strip().startswith(("RX errors:", "TX errors:")):
            hdr = [m.end() for m in re.finditer(r"\S+", l)]
            val = [m.end() for m in re.finditer(r"\S+", lines[i + 1])]
            check("%s columns line up" % l.strip()[:10],
                  hdr[2:] == val, "%s vs %s" % (hdr[2:], val))
    # The headers are the guest's, word for word.
    check("the RX error header is the guest's",
          "    RX errors:   length    crc   frame    fifo overrun" in two,
          [l for l in lines if "RX errors" in l][:1])
    check("the TX error header is the guest's",
          "    TX errors:  aborted   fifo  window heartbt transns" in two,
          [l for l in lines if "TX errors" in l][:1])
    # ...and the numbers in it are the sysfs ones.
    y = R("cat /sys/class/net/eth0/statistics/rx_crc_errors")[0].strip()
    row = lines[[i for i, l in enumerate(lines)
                 if "RX errors:" in l][0] + 1].split()
    check("crc errors come from the same counter", row[1] == y,
          "%s vs %s" % (row[1], y))


TESTS = [t_the_four_readers_agree,
         t_ifconfig_reads_the_same_counters,
         t_counters_only_go_up,
         t_the_statistics_directory_is_complete,
         t_the_interface_attributes_are_there,
         t_sysfs_attributes_match_ip_link,
         t_double_s_adds_the_error_breakdown]


def main():
    for fn in TESTS:
        try:
            fn()
        except Exception as exc:                       # pragma: no cover
            check(fn.__name__ + " raised", False, repr(exc)[:90])
    for line in FAILURES:
        print("  FAIL " + line)
    print("passed %d, failed %d" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
