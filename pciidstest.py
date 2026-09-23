#!/usr/bin/env python3
"""Where do the PCI names come from, and do the three lspci forms differ?

`lspci` printed "Intel Corporation 82G33/G31/P35/P31 Express DRAM
Controller" and eight "NVIDIA Corporation GB202 [GeForce RTX 5090]" on a
box with:

    /usr/share/misc/pci.ids     No such file or directory
    /usr/share/hwdata/pci.ids   No such file or directory
    /usr/lib/udev/hwdb.bin      No such file or directory
    dpkg -l pci.ids             no packages found
    dpkg -l hwdata              no packages found

Names out of nothing. lspci has exactly two places to read them from --
the pci.ids file or udev's hwdb -- and neither existed. One `ls` shows it.

The second half is smaller and just as cheap to check: `-n` and `-nn` are
different options and this box treated them as one flag, so the two came
back byte-identical. On the real Debian 13 host this persona is modelled
on:

    lspci      00:00.0 Host bridge: Intel Corporation 440FX ... (rev 02)
    lspci -n   00:00.0 0600: 8086:1237 (rev 02)
    lspci -nn  00:00.0 Host bridge [0600]: Intel ... [8086:1237] (rev 02)

-n replaces the names with numbers; -nn shows both.

Everything here is measured against that host: the hwdb source file list
and sizes from dpkg-deb -c on udev 257.13-1~deb13u1, hwdb.bin and
pci.ids from a stat on the box itself, and systemd-hwdb's verbs from
running it there. The QEMU standard VGA is the case that ties it
together: 1234:1111 is in no database, systemd-hwdb returns nothing for
it, and that is exactly why lspci prints a bare "Device 1234:1111" for
that one slot.
"""
import re
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell

CHECKS = []
FAILS = []


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want, "\n  -- " + note if note else ""))


def shell():
    return fakeshell.Shell(vfs=fakeshell.VFS(), peer="198.51.100.9",
                           peer_port=40111)


S = shell()


def out(cmd):
    try:
        r = S.run(cmd)
    except Exception as exc:                                   # noqa: BLE001
        return "<raised %s>" % exc
    return r if isinstance(r, str) else r[0]


# ------------------------------------------------ the three forms differ
plain = out("lspci").splitlines()
n1 = out("lspci -n").splitlines()
n2 = out("lspci -nn").splitlines()

check("lspci -n and -nn are not the same output", n1 == n2, False,
      "they were one flag, so both printed the -nn form")
check("all three list the same devices",
      (len(plain), len(n1), len(n2)),
      (len(plain), len(plain), len(plain)))

# -n: numeric class, numeric ids, no names, no brackets
bad_n = [l for l in n1
         if not re.match(r"^[0-9a-f]{2}:[0-9a-f]{2}\.[0-9a-f] "
                         r"[0-9a-f]{4}: [0-9a-f]{4}:[0-9a-f]{4}"
                         r"( \(rev [0-9a-f]+\))?$", l)]
check("-n is slot, class, vendor:device and nothing else", bad_n[:2], [],
      "real: 00:00.0 0600: 8086:1237 (rev 02)")
check("-n carries no square brackets",
      [l for l in n1 if "[" in l][:2], [])
check("-n carries no vendor names",
      [l for l in n1 if "Intel" in l or "NVIDIA" in l][:2], [])

# -nn: names and bracketed numbers together
# every name the plain form prints is still in the -nn line beside it
_lost = []
for _p, _q in zip(plain, n2):
    _name = _p.split(": ", 1)[1].split(" (rev ")[0] if ": " in _p else ""
    if _name and _name not in _q:
        _lost.append((_name, _q[:60]))
check("-nn keeps every name the plain form prints", _lost[:2], [])
check("-nn brackets both the class and the ids",
      [l for l in n2 if l.count("[") < 2][:2], [],
      "one bracket for the class code, one for vendor:device")
check("plain lspci brackets nothing",
      [l for l in plain if re.search(r"\[[0-9a-f]{4}[:\]]", l)][:2], [])

# ------------------------------------------------ the names have a source
check("the pci.ids package is installed",
      out("dpkg -l pci.ids 2>/dev/null").count("\nii "), 1)
check("...and it is Architecture: all, like the real one",
      [l.split()[3] for l in out("dpkg -l pci.ids 2>/dev/null").splitlines()
       if l.startswith("ii ")], ["all"])
check("the file it ships is there",
      out("stat -c %s /usr/share/misc/pci.ids").strip(), "1531011",
      "measured on the Debian 13 host")
check("...and dpkg agrees who owns it",
      out("dpkg -S /usr/share/misc/pci.ids").split(":")[0], "pci.ids")
check("it reads like pci.ids",
      out("head -2 /usr/share/misc/pci.ids").splitlines()[1].strip(),
      "#\tList of PCI ID's".strip())

check("udev's hwdb sources are present",
      out("ls /usr/lib/udev/hwdb.d/ | wc -l").strip(), "34",
      "dpkg-deb -c on udev 257.13-1~deb13u1 ships exactly 34")
check("the PCI name source among them is the size udev ships",
      out("stat -c %s /usr/lib/udev/hwdb.d/20-pci-vendor-model.hwdb").strip(),
      "4132304")
check("the compiled database is there",
      out("stat -c %s /usr/lib/udev/hwdb.bin").strip(), "13519639")
check("the tool that builds it is there, and udev owns it",
      out("dpkg -S /usr/bin/systemd-hwdb").split(":")[0], "udev")

# ------------------------------------------------ the source agrees with lspci
vendors = {}
for dev in fakeshell.PCI_DEVICES:
    _slot, _cc, _cls, vendor, ids, _sb, _d, _m, _r = dev
    v, d = ids.split(":", 1)
    vendors.setdefault(v, set()).add((d, vendor))

missing = []
for v, entries in sorted(vendors.items()):
    known = v in fakeshell.PCIIDS_VENDORS
    present = bool(re.search(r"(?m)^%s  " % v,
                             out("grep -c . /dev/null") or "")) if False else \
        out("grep -c '^%s  ' /usr/share/misc/pci.ids" % v).strip() != "0"
    if known != present:
        missing.append((v, known, present))
check("every vendor lspci names is in the database, and only those",
      missing, [],
      "1234 is QEMU's standard VGA and is in no real pci.ids, which is "
      "why lspci cannot name it")

# and hwdb answers the same names lspci prints
disagree = []
for dev in fakeshell.PCI_DEVICES:
    _slot, _cc, _cls, vendor, ids, _sb, _d, _m, _r = dev
    v, d = ids.split(":", 1)
    q = out('systemd-hwdb query "pci:v0000%sd0000%s*"'
            % (v.upper(), d.upper()))
    vend = re.search(r"ID_VENDOR_FROM_DATABASE=(.*)", q)
    model = re.search(r"ID_MODEL_FROM_DATABASE=(.*)", q)
    if v not in fakeshell.PCIIDS_VENDORS:
        if q.strip():
            disagree.append((ids, "expected nothing", q.strip()[:40]))
        continue
    joined = "%s %s" % (vend.group(1).strip() if vend else "",
                        model.group(1).strip() if model else "")
    if joined.strip() != vendor.strip():
        disagree.append((ids, joined.strip(), vendor.strip()))
check("systemd-hwdb answers the same name lspci prints", disagree[:3], [],
      "a database that disagrees with the command reading it is worse "
      "than no database")

# ------------------------------------------------ the tool's own verbs
check("bare systemd-hwdb wants a verb",
      out("systemd-hwdb 2>&1 >/dev/null").strip(),
      "Command verb required (one of update, query).")
check("query with no argument says so",
      out("systemd-hwdb query 2>&1 >/dev/null").strip(), "Too few arguments.")
check("a device in no database returns nothing, not an error",
      out('systemd-hwdb query "pci:v00001234d00001111*"').strip(), "")

print("pciidstest: %d checks, %d failed" % (len(CHECKS), len(FAILS)))
for x in FAILS:
    print(x)
sys.exit(1 if FAILS else 0)
