"""The disk's identity, and the commands that report it.

Recorded for its own sweep at the end of sweep 203, which found udevadm
reporting ID_PART_TABLE_TYPE=gpt while blkid printed this:

    /dev/sda1:  ... PARTUUID="b41c9e2a-01"
    /dev/sda14: PARTUUID="b41c9e2a-14"
    /dev/sda15: ... PARTUUID="b41c9e2a-15"

That is an MBR disk identifier plus a partition index -- the form a *DOS*
label produces. No GPT emits it, and this layout is unambiguously GPT:
sda14 is a BIOS boot partition and sda15 an ESP, neither of which an MBR
can express. partuuid_of's own docstring said "the GPT entry's UUID" while
its body built the DOS form, and the comment at blkid's call site had
already noted the shape was one "no partition table produces".

Then lsblk turned out to be silent about it entirely:

    $ lsblk -o NAME,PARTUUID,PARTTYPENAME,SERIAL,MODEL,VENDOR
    guest    sda                                                drive-scsi0 QEMU HARDDISK QEMU
             |-sda1  74147049-...  Linux root (x86-64)
             |-sda14 444d85db-...  BIOS boot
             `-sda15 5e170fc7-...  EFI System
    ours     sda
             |-sda1
             |-sda14
             `-sda15

Five blank columns. PARTUUID had a value in blkid and a symlink under
/dev/disk/by-partuuid named after it -- three readers of one fact, one of
them silent -- and MODEL, VENDOR and SERIAL were blank while `udevadm
info` published ID_MODEL, ID_VENDOR and ID_SERIAL_SHORT for the same
device. One box, two answers, in both cases.

The PARTUUIDs are derived from the disk's own identity and the partition
number, so they are stable across restarts and distinct per partition: an
attacker who notes one and comes back has to find the same one. And
/dev/disk/by-partuuid is now built from partuuid_of rather than a second
copy of the strings, so the two cannot drift.

Usage:  python3 partuuidtest.py
"""

import re
import sys

import fakeshell

CHECKS, FAILS = [], []
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}"
                     r"-[0-9a-f]{4}-[0-9a-f]{12}$")


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


def blkid_partuuid(dev):
    """PARTUUID as blkid reports it, or ""."""
    for line in r("blkid").splitlines():
        if line.startswith("/dev/%s:" % dev):
            m = re.search(r'PARTUUID="([^"]*)"', line)
            return m.group(1) if m else ""
    return ""


def lsblk_col(dev, col):
    """One lsblk column for one row, or "" when it prints nothing.

    Everything after the device name, not the next whitespace-delimited
    token: real values contain spaces -- "QEMU HARDDISK", "EFI System" --
    and splitting on whitespace silently truncated them to "QEMU" and
    "EFI", which made this suite fail against a correct tree.
    """
    for line in r("lsblk -no NAME,%s" % col).splitlines():
        flat = line.replace("├─", "").replace("└─", "").replace("│", " ")
        stripped = flat.strip()
        if not stripped:
            continue
        first, _, rest = stripped.partition(" ")
        if first == dev:
            return rest.strip()
    return "<no row>"


PARTS = ("sda1", "sda14", "sda15")

# ------------------------------------------------ the form is a GPT form
for part in PARTS:
    got = blkid_partuuid(part)
    check("blkid PARTUUID for %s is a full UUID" % part,
          bool(UUID_RE.match(got)), True,
          "an MBR id plus an index -- 'b41c9e2a-01' -- is what a DOS label "
          "produces, and this layout is GPT. got %r" % got)
check("...and they are all different",
      len({blkid_partuuid(p) for p in PARTS}), 3)
check("...and none is the disk identifier with an index",
      any(blkid_partuuid(p).endswith(("-01", "-14", "-15")) for p in PARTS),
      False)

# ------------------------------------------------------ and it is stable
first = {p: blkid_partuuid(p) for p in PARTS}
sh2 = shell()
again = {}
for p in PARTS:
    for line in sh2.run("blkid").splitlines():
        if line.startswith("/dev/%s:" % p):
            m = re.search(r'PARTUUID="([^"]*)"', line)
            again[p] = m.group(1) if m else ""
check("a PARTUUID is the same on a fresh box", again, first,
      "someone who notes one and comes back has to find the same one, so "
      "it cannot be random per boot")

# --------------------------------- every reader of it says the same thing
links = set(r("ls /dev/disk/by-partuuid").split())
check("/dev/disk/by-partuuid holds one link per partition", len(links), 3)
check("...named exactly as blkid reports them",
      links, {blkid_partuuid(p) for p in PARTS},
      "these were a second hardcoded copy of the strings; they are built "
      "from partuuid_of now")
for part in PARTS:
    check("by-partuuid/%s points at it" % part,
          r("readlink /dev/disk/by-partuuid/%s" % blkid_partuuid(part)),
          "../../%s" % part)
for part in PARTS:
    check("lsblk PARTUUID for %s matches blkid" % part,
          lsblk_col(part, "PARTUUID"), blkid_partuuid(part),
          "this column printed nothing at all")

# --------------------------------------------- the GPT type is published
for part, name in (("sda1", "Linux root (x86-64)"),
                   ("sda14", "BIOS boot"), ("sda15", "EFI System")):
    check("lsblk PARTTYPENAME for %s" % part,
          lsblk_col(part, "PARTTYPENAME"), name,
          "the type GUIDs are universal GPT constants")
check("sda14's type GUID is the BIOS boot one",
      lsblk_col("sda14", "PARTTYPE"),
      "21686148-6449-6e6f-744e-656564454649")
check("a whole disk has no partition type",
      lsblk_col("sda", "PARTTYPENAME"), "")

# ------------------------------- the disk's identity, as udevadm has it
info = r("udevadm info -q all -n /dev/sda")
check("lsblk MODEL agrees with udevadm ID_MODEL",
      lsblk_col("sda", "MODEL").replace(" ", "_"),
      next((l.split("=", 1)[1] for l in info.splitlines()
            if l.startswith("E: ID_MODEL=")), "<none>"),
      "lsblk printed nothing while udevadm had the answer")
check("lsblk VENDOR agrees with udevadm",
      lsblk_col("sda", "VENDOR"),
      next((l.split("=", 1)[1] for l in info.splitlines()
            if l.startswith("E: ID_VENDOR=")), "<none>"))
check("lsblk SERIAL agrees with udevadm",
      lsblk_col("sda", "SERIAL"),
      next((l.split("=", 1)[1] for l in info.splitlines()
            if l.startswith("E: ID_SERIAL_SHORT=")), "<none>"))
check("the CD-ROM has its own model",
      lsblk_col("sr0", "MODEL"), "QEMU DVD-ROM")
check("a partition does not claim the disk's model",
      lsblk_col("sda1", "MODEL"), "",
      "MODEL belongs to the device, not the partition")

# --------------------------------- and the layout still says gpt
check("udevadm still reports a gpt table",
      "ID_PART_TABLE_TYPE=gpt" in info, True)
check("the fstab UUID still resolves",
      r("readlink /dev/disk/by-uuid/%s"
        % r("grep ^UUID= /etc/fstab").split("=", 1)[1].split()[0]),
      "../../sda1", "changing PARTUUIDs must not disturb by-uuid")

for f in FAILS:
    print(" ", f)
print("   partuuid: %d checks, %d differ" % (len(CHECKS), len(FAILS)))
sys.exit(1 if FAILS else 0)
