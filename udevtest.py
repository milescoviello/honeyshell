"""udev: the rules directory, and the command you run after writing one.

Inventory search for persistence mechanisms with no coverage. A udev rule
is one: RUN+= runs as root on a matching event, and the pair you run to
make it take effect is

    udevadm control --reload
    udevadm trigger

Both printed "udevadm 257.13" here. So did `udevadm settle`, `udevadm
info` and `udevadm --version` -- it was a stock stub answering every
subcommand with the same banner, and the box's own instrumentation logged
each invocation as an unknown_command while this was being probed.

Measured on the guest, Debian 13.6:

    udevadm --version                    257          (a bare number)
    udevadm control --reload             (silent)     rc 0
    udevadm trigger --dry-run ...        (silent)     rc 0
    udevadm settle                       (silent)     rc 0
    udevadm info -q all -n /dev/sda      P: /devices/...  a property dump

And the surroundings were thin: /etc/udev was an empty directory against
the guest's four entries, and /usr/lib/udev/rules.d did not exist at all
against 45 rule files. /etc/udev/rules.d -- the one an attacker writes
into -- is correctly empty on both.

The device path in `info` is read from this box's own /sys rather than
copied from the guest: our sda hangs off 0000:00:05.0 directly where the
guest's has a bridge in between, so the guest's string would have
described a machine this is not.

Usage:  python3 udevtest.py
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
    try:
        return int(r("ls %s 2>/dev/null | wc -l" % d).strip())
    except ValueError:
        return -1


# --------------------------------------------------------- the surroundings
check("/etc/udev has what Debian puts there",
      sorted(r("ls /etc/udev").split()),
      ["hwdb.d", "iocost.conf", "rules.d", "udev.conf"],
      "it was an empty directory")
check("udev.conf is the real one",
      "see udev.conf(5) for details" in r("head -1 /etc/udev/udev.conf"),
      True)
check("the shipped rules are there", count("/usr/lib/udev/rules.d") >= 40,
      True, "the guest has 45, we had none; got %d"
            % count("/usr/lib/udev/rules.d"))
check("...and reachable through the merged-/usr symlink",
      count("/lib/udev/rules.d"), count("/usr/lib/udev/rules.d"),
      "/lib is a symlink to usr/lib, so writing under /lib created nodes "
      "the listing could not see")
check("a few of them by name",
      all(r("test -f /usr/lib/udev/rules.d/%s && echo y || echo n" % f) == "y"
          for f in ("99-systemd.rules", "60-block.rules",
                    "60-persistent-storage.rules", "80-drivers.rules")),
      True)
check("/etc/udev/rules.d is empty, as on the guest",
      count("/etc/udev/rules.d"), 0,
      "this is the directory an attacker writes into; Debian ships none")

# ------------------------------------------- a rule can actually be planted
check("a udev rule can be written",
      r("echo 'ACTION==\"add\", SUBSYSTEM==\"block\", "
        "RUN+=\"/tmp/x\"' > /etc/udev/rules.d/99-x.rules; echo rc=$?"),
      "rc=0")
check("...and read back", "RUN+=" in r("cat /etc/udev/rules.d/99-x.rules"),
      True)
check("...and it shows in the directory", count("/etc/udev/rules.d"), 1)

# ------------------------------------------------------ udevadm answers
check("--version is a bare number", r("udevadm --version"), "257",
      "the stub printed 'udevadm 257.13'")
for verb in ("control --reload", "trigger --dry-run --subsystem-match=block",
             "settle"):
    out = r("udevadm %s" % verb)
    check("udevadm %s is silent" % verb.split()[0], out, "",
          "this is what you run after planting a rule, and it printed a "
          "version banner; got %r" % out[:60])
    check("udevadm %s exits 0" % verb.split()[0],
          r("udevadm %s >/dev/null 2>&1; echo $?" % verb), "0")

# ---------------------------------------------------------- info answers
def line0(text):
    """The first line, or "". splitlines()[0] raises against a tree whose
    info prints nothing, and a suite that raises reports a traceback
    instead of the failures it was written to find -- the ninth time that
    rule has come up here."""
    parts = text.splitlines()
    return parts[0] if parts else ""


def after(text, sep):
    """The part past sep, or "" -- same reason as line0."""
    return text.split(sep, 1)[1] if sep in text else ""


info = r("udevadm info -q all -n /dev/sda")
check("info prints a device path, not a banner",
      info.startswith("P: /devices/"), True, "got %r" % info[:70])
check("...that matches this box's own sysfs",
      after(line0(info), ": "),
      "/devices/" + r("readlink /sys/block/sda").split("devices/", 1)[-1],
      "the path has to be ours, not the guest's")
for field in ("M: sda", "U: block", "T: disk", "N: sda"):
    check("info carries %r" % field, field in info, True)
for key in ("DEVNAME=/dev/sda", "MAJOR=8", "MINOR=0", "SUBSYSTEM=block",
            "ID_BUS=scsi", "ID_PART_TABLE_TYPE=gpt"):
    check("info property %s" % key.split("=")[0], key in info, True)
check("the major:minor agrees with /sys",
      "MAJOR=%s" % r("cat /sys/block/sda/dev").split(":")[0] in info, True)

check("a CD-ROM is described as one",
      ("T: rom" in r("udevadm info -q all -n /dev/sr0")
       and "ID_TYPE=cd" in r("udevadm info -q all -n /dev/sr0")), True)
check("-q property gives bare KEY=VALUE lines",
      line0(r("udevadm info -q property -n /dev/sda")),
      "DEVPATH=/devices/"
      + r("readlink /sys/block/sda").split("devices/", 1)[-1])
check("-q name gives the name", r("udevadm info -q name -n /dev/sda"), "sda")

check("an unknown device is refused",
      r("udevadm info -q all -n /dev/nope 2>&1"),
      'Unknown device "/dev/nope": No such device')
check("...with a non-zero status",
      r("udevadm info -q all -n /dev/nope >/dev/null 2>&1; echo $?"), "4")

for f in FAILS:
    print(" ", f)
print("   udev: %d checks, %d differ" % (len(CHECKS), len(FAILS)))
sys.exit(1 if FAILS else 0)
