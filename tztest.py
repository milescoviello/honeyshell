#!/usr/bin/env python3
"""What time is it here, where does the box think it is, and who says so?

The clock is one fact with a lot of readers -- date, uptime, /proc/uptime,
/proc/stat, who -b, last, timedatectl, journalctl --list-boots, loginctl --
and the *zone* is a second fact that half of them quote. Those two were
being answered from four different places, and one of the places was empty.

    dpkg -l tzdata            ii  tzdata  ...  installed
    ls -l /etc/localtime      -> /usr/share/zoneinfo/Etc/UTC
    readlink -f /etc/localtime   (nothing)
    ls /usr/share/zoneinfo    No such file or directory

The zone database was not there at all. The symlink pointed into a
directory that did not exist, so `cat /etc/localtime` failed on a box that
reports tzdata installed and prints a zone in `timedatectl` -- and
`TZ=America/New_York date`, the one-line way to ask whether a box has zone
data, silently returned UTC. All 443 files, 51 compatibility symlinks and
15 directories are now seeded from the guest's own tree; see tzdb.py.

The rest of the axis:

  * `date +%Z` said GMT while `date` with no format said UTC. The default
    format carried a literal "UTC" and %Z went through gmtime, whose struct
    is labelled GMT. One command, two spellings, and the guest says UTC to
    both.
  * /etc/timezone existed here and does not exist on trixie -- a second copy
    of a fact that lives in /etc/localtime, and one more thing to drift.
  * `timedatectl` had no "RTC time" row and two of its keys were a column
    out: systemd right-aligns every key to the longest one present.
  * `systemctl get-default` returned an empty line.
  * `systemd-analyze` printed the version banner and a usage line with rc 1
    -- the unimplemented-binary fallback -- where the real one reports the
    boot breakdown and names the target it reached, which has to be the
    target get-default names.

Reference output measured on the guest.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402
import tzdb                                                     # noqa: E402

PASS, FAIL = 0, 0
FAILURES = []


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
    else:
        FAIL += 1
        FAILURES.append("%-56s %s" % (name, detail))


S = fs.Shell(fs.VFS())
S.exec_mode = True


def R(cmd, s=None):
    t = s or S
    t._err = []
    out = t.run(cmd)
    return out or "", "".join(t._err), t.last_rc


# ---------------------------------------------------------------------------
# The zone database exists, and the symlink lands in it
# ---------------------------------------------------------------------------
def t_localtime_resolves():
    out, _e, rc = R("ls -l /etc/localtime")
    check("/etc/localtime is a symlink", rc == 0 and " -> " in out, out[:70])
    check("it points where Debian points it",
          out.rstrip().endswith("-> /usr/share/zoneinfo/Etc/UTC"), out[:80])
    tgt, _e, rc = R("readlink -f /etc/localtime")
    check("readlink -f resolves it", tgt.strip()
          == "/usr/share/zoneinfo/Etc/UTC", repr(tgt))
    out, err, rc = R("head -c 5 /etc/localtime")
    check("reading it gives TZif magic", out == "TZif2", repr(out) + err[:40])
    check("cat /etc/localtime exits 0", R("cat /etc/localtime")[2] == 0,
          R("cat /etc/localtime")[1][:60])
    size, _e, _r = R("stat -c %s /usr/share/zoneinfo/Etc/UTC")
    check("Etc/UTC is the size the guest's is", size.strip() == "114",
          size.strip())


def t_the_tree_is_the_guests():
    out, _e, rc = R("ls /usr/share/zoneinfo/")
    check("the directory lists", rc == 0, out[:60])
    got = set(out.split())
    for name in ("Africa", "America", "Etc", "Europe", "Pacific", "UTC",
                 "zone.tab", "zone1970.tab", "iso3166.tab", "leapseconds",
                 "tzdata.zi", "posixrules", "localtime"):
        check("zoneinfo has %s" % name, name in got, sorted(got)[:6])
    nfiles = R("find /usr/share/zoneinfo -type f | wc -l")[0].strip()
    check("443 regular files, as on the guest", nfiles == "443", nfiles)
    nlinks = R("find /usr/share/zoneinfo -type l | wc -l")[0].strip()
    check("51 compatibility symlinks", nlinks == "51", nlinks)
    # The old spellings really are links, not copies.
    out = R("ls -l /usr/share/zoneinfo/UTC")[0]
    check("UTC is a link to Etc/UTC", out.rstrip().endswith("-> Etc/UTC"),
          out[:70])
    check("and it resolves",
          R("readlink -f /usr/share/zoneinfo/UTC")[0].strip()
          == "/usr/share/zoneinfo/Etc/UTC",
          R("readlink -f /usr/share/zoneinfo/UTC")[0].strip())


def t_the_package_and_the_files_agree():
    row = [l for l in R("dpkg -l tzdata")[0].splitlines()
           if l.startswith("ii")]
    check("dpkg says tzdata is installed", bool(row), "not installed")
    if row:
        check("with the guest's version", row[0].split()[2]
              == "2026b-0+deb13u1", row[0].split()[2])
        check("and a real description",
              "time zone" in " ".join(row[0].split()[4:]),
              " ".join(row[0].split()[4:])[:50])
    # /etc/timezone is gone in trixie, and dpkg owns no such path.
    check("/etc/timezone does not exist", R("cat /etc/timezone")[2] != 0,
          R("cat /etc/timezone")[0][:40])
    check("nothing claims to own it",
          "no path found" in R("dpkg -S /etc/timezone")[1]
          or R("dpkg -S /etc/timezone")[2] != 0,
          R("dpkg -S /etc/timezone")[0][:50])


# ---------------------------------------------------------------------------
# One name for the zone
# ---------------------------------------------------------------------------
def t_date_spells_the_zone_one_way():
    plain = R("date")[0].strip()
    zed = R("date +%Z")[0].strip()
    check("date +%Z is UTC, not GMT", zed == "UTC", zed)
    check("the default format uses the same word", zed in plain.split(),
          plain)
    check("date +%z is the offset", R("date +%z")[0].strip() == "+0000",
          R("date +%z")[0].strip())
    # timedatectl and the symlink have to name the same zone.
    td = R("timedatectl")[0]
    m = re.search(r"Time zone: (\S+)", td)
    check("timedatectl names a zone", m is not None, td[:60])
    link = R("readlink /etc/localtime")[0].strip()
    if m:
        check("and it is the one /etc/localtime points at",
              link.endswith("/" + m.group(1)),
              "%s vs %s" % (m.group(1), link))
    # -d and -r format in the same zone as everything else.
    check("date -d agrees about the zone",
          R('date -d "2026-01-15 12:00" +%Z')[0].strip() == "UTC",
          R('date -d "2026-01-15 12:00" +%Z')[0].strip())


def t_tz_is_read_from_the_environment():
    """`TZ=X date` is how you ask whether a box has zone data at all."""
    out = R('TZ=America/New_York date +"%Z %z"')[0].strip()
    check("TZ=America/New_York shifts the zone",
          out in ("EDT -0400", "EST -0500"), out)
    out = R('TZ=Asia/Shanghai date +"%Z %z"')[0].strip()
    check("TZ=Asia/Shanghai shifts the zone", out == "CST +0800", out)
    # The hours have to move with it.
    utc = int(R("date +%H")[0].strip())
    ny = int(R("TZ=America/New_York date +%H")[0].strip())
    check("and the clock moves too", (utc - ny) % 24 in (4, 5),
          "utc %d, ny %d" % (utc, ny))
    # A zone with no file falls back, as the real one does.
    check("an unknown zone falls back to UTC",
          R("TZ=Not/AZone date +%Z")[0].strip() == "UTC",
          R("TZ=Not/AZone date +%Z")[0].strip())
    # ...and the fallback is decided by this box's own tree.
    check("the zone it accepted is a file here",
          R("test -f /usr/share/zoneinfo/America/New_York")[2] == 0,
          "missing")
    check("the one it refused is not",
          R("test -e /usr/share/zoneinfo/Not/AZone")[2] != 0, "present")


# ---------------------------------------------------------------------------
# timedatectl's shape, and the boot
# ---------------------------------------------------------------------------
def t_timedatectl_has_systemds_shape():
    out, _e, rc = R("timedatectl")
    check("timedatectl exits 0", rc == 0, "rc=%s" % rc)
    keys = [l.split(":")[0].strip() for l in out.splitlines() if ":" in l]
    check("every row the guest prints is here",
          keys == ["Local time", "Universal time", "RTC time", "Time zone",
                   "System clock synchronized", "NTP service",
                   "RTC in local TZ"], str(keys))
    cols = {l.index(":") for l in out.splitlines() if ":" in l}
    check("all the keys are right-aligned to one column", cols == {25},
          str(sorted(cols)))


def t_the_boot_is_one_event():
    """Everything that names the boot has to name the same instant."""
    up = R("cat /proc/uptime")[0].split()
    check("/proc/uptime parses", len(up) == 2, str(up))
    btime = int(re.search(r"btime (\d+)", R("grep btime /proc/stat")[0])
                .group(1))
    now = int(R("date +%s")[0].strip())
    check("btime plus uptime is now", abs(now - btime - float(up[0])) < 3,
          "now %d, btime %d, up %s" % (now, btime, up[0]))
    boot_s = R("uptime -s")[0].strip()
    check("uptime -s is btime, formatted",
          boot_s == R("date -d @%d '+%%Y-%%m-%%d %%H:%%M:%%S'"
                      % btime)[0].strip(),
          "%s vs btime %d" % (boot_s, btime))
    whob = R("who -b")[0]
    check("who -b agrees to the minute", boot_s[:16] in whob,
          "%s not in %r" % (boot_s[:16], whob.strip()))
    lastr = R("last reboot")[0]
    check("last reboot agrees", "still running" in lastr, lastr[:60])
    boots = R("journalctl --list-boots")[0]
    check("the journal's first entry is the boot",
          boot_s[:10] in boots, boots[:100])


def t_systemd_analyze_reports_the_boot():
    out, err, rc = R("systemd-analyze")
    check("systemd-analyze with no arguments exits 0", rc == 0,
          "rc=%s %s" % (rc, (out + err)[:50]))
    check("it is the same as `time`", out == R("systemd-analyze time")[0],
          "differs")
    check("it reports the startup breakdown",
          out.startswith("Startup finished in "), (out + err)[:70])
    m = re.match(r"Startup finished in ([\d.]+)s \(kernel\) \+ ([\d.]+)s "
                 r"\(userspace\) = ([\d.]+)s", out)
    check("the parts add up to the total",
          m and abs(float(m.group(1)) + float(m.group(2))
                    - float(m.group(3))) < 0.002,
          out.splitlines()[0] if out else "")
    target = R("systemctl get-default")[0].strip()
    check("get-default names a target", target.endswith(".target"),
          repr(target))
    check("systemd-analyze reached that same target",
          target in out, "%s not in %r" % (target, out.splitlines()[-1:]))
    blame = R("systemd-analyze blame")[0].splitlines()
    check("blame lists units", len(blame) > 3, str(blame[:2]))
    check("blame is sorted slowest first",
          blame == sorted(blame, key=lambda l: -_ms(l)), str(blame[:3]))
    units = {l.split()[0] for l in R("systemctl list-units --type=service "
                                     "--no-legend")[0].splitlines()
             if l.split()}
    unknown = [l.split()[1] for l in blame if l.split()[1] not in units]
    check("every unit blame names is a unit systemctl lists",
          not unknown, str(unknown[:4]))
    check("an unknown verb is refused",
          R("systemd-analyze bogus")[2] == 1,
          "rc=%s" % R("systemd-analyze bogus")[2])


def _ms(line):
    tok = line.split()[0]
    return float(tok[:-2]) if tok.endswith("ms") else float(tok[:-1]) * 1000


TESTS = [t_localtime_resolves,
         t_the_tree_is_the_guests,
         t_the_package_and_the_files_agree,
         t_date_spells_the_zone_one_way,
         t_tz_is_read_from_the_environment,
         t_timedatectl_has_systemds_shape,
         t_the_boot_is_one_event,
         t_systemd_analyze_reports_the_boot]


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
