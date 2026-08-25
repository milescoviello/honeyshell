#!/usr/bin/env python3
"""How much hardware is this, and do the answers agree?

203.0.113.62 asked this box on 2026-08-25. It logged in as root on its
first try of that connection, spent four and a half seconds, and every
command was about the hardware:

    lspci | grep VGA | cut -f5- -d ' '
    nvidia-smi -q | grep "Product Name" | head -n 1 | awk ...
    lspci | grep "3D controller" | cut -f5- -d ' '
    nproc --all

It was deciding whether the box was worth hijacking -- a GPU to mine on or
a CPU count worth the trouble. Then it left. That is the current shape of
the traffic, and nothing here had ever been asked whether the hardware
story holds together.

It mostly did. What did not:

  * getconf was five variables and silence for everything else.
    `getconf _NPROCESSORS_ONLN` said 4, `getconf _NPROCESSORS_CONF` said
    nothing at all, and /proc/cpuinfo said 4. Three ways of asking one
    question with one of them mute. `getconf -a` printed zero lines where
    the real one prints 322. An empty answer is not a wrong number; it is
    an obviously fake box, and CLK_TCK and _PHYS_PAGES are exactly what an
    installer reads before it sizes itself.

  * `ps -eo psr` printed "-" for every process while /proc/<pid>/stat
    field 39 carried the real CPU. psr was not in ps's column table at
    all. A four-CPU box on which nothing has a CPU number.

The reference values were measured on the guest, and the derivation rules
with them rather than assumed:

  * _PHYS_PAGES * PAGESIZE == MemTotal, exactly.
  * _AVPHYS_PAGES tracks MemFree, not MemAvailable (guest: 79900 pages =
    319600 kB against MemFree 319852 kB, sampled a moment apart).
  * getconf prints one cache instance and lscpu prints the total across
    instances: guest lscpu "L2 8 MiB (2 instances)" goes with getconf
    LEVEL2_CACHE_SIZE 4194304, and 8 MiB / 2 is exactly that.

One thing checked and deliberately not "fixed": `dmesg | grep smpboot` is
empty here, and it is empty on the real guest too. It looked like a gap
and measuring it was what stopped a wrong change.

Usage:  python3 hwprofiletest.py
"""

import sys

import fakeshell as F

CHECKS, FAILS = [], []


def check(name, got, want):
    CHECKS.append(name)
    if got != want:
        FAILS.append((name, got, want))


def sh():
    return F.Shell()


def num(text):
    """int(), or None when the box answered with nothing.

    Needed because the bug being tested for is an *empty* answer. Calling
    int("") raises, and a suite that dies on the first defect never reports
    the other five -- against the pre-fix build this crashed in the third
    test and the psr and lspci checks never ran at all.
    """
    try:
        return int(str(text).strip())
    except (TypeError, ValueError):
        return None


def t_cpu_count_agrees_everywhere():
    """Every way of asking how many CPUs, against one another.

    Not against a hardcoded 4 -- against each other, so the persona can
    change and this still means something.
    """
    s = sh()
    n = s.run("nproc").strip()
    check("nproc is a number", n.isdigit(), True)
    if not n.isdigit():
        return
    ways = {
        "nproc --all": s.run("nproc --all").strip(),
        "getconf _NPROCESSORS_ONLN": s.run("getconf _NPROCESSORS_ONLN").strip(),
        "getconf _NPROCESSORS_CONF": s.run("getconf _NPROCESSORS_CONF").strip(),
        "getconf NPROCESSORS_ONLN": s.run("getconf NPROCESSORS_ONLN").strip(),
        "getconf NPROCESSORS_CONF": s.run("getconf NPROCESSORS_CONF").strip(),
        "/proc/cpuinfo": s.run("grep -c ^processor /proc/cpuinfo").strip(),
        "lscpu CPU(s)": s.run(
            "lscpu | grep -E '^CPU\\(s\\):' | awk '{print $2}'").strip(),
        "lscpu -p": s.run("lscpu -p=cpu | grep -vc '^#'").strip(),
        "/sys cpu dirs": s.run(
            "ls -d /sys/devices/system/cpu/cpu[0-9]* | wc -l").strip(),
        "/proc/stat cpuN": s.run("grep -c '^cpu[0-9]' /proc/stat").strip(),
    }
    for label, got in ways.items():
        check("cpu count via %s" % label, got, n)

    # The range forms have to describe the same count.
    last = str((num(n) or 1) - 1)
    for f in ("online", "present", "possible"):
        check("/sys/devices/system/cpu/%s" % f,
              s.run("cat /sys/devices/system/cpu/%s" % f).strip(),
              "0-%s" % last)
    check("taskset affinity spans them all",
          s.run("taskset -pc 1").strip().endswith("0-%s" % last), True)


def t_getconf_answers_at_all():
    """The stub answered five variables and returned "" for the rest."""
    s = sh()
    check("getconf -a line count", len(s.run("getconf -a").splitlines()), 322)
    for v in ("_NPROCESSORS_CONF", "CLK_TCK", "_PHYS_PAGES", "_AVPHYS_PAGES",
              "OPEN_MAX", "GNU_LIBC_VERSION", "LEVEL1_DCACHE_SIZE",
              "LEVEL2_CACHE_SIZE", "LEVEL3_CACHE_SIZE"):
        check("getconf %s is not empty" % v, s.run("getconf %s" % v).strip() != "",
              True)
    # Values measured on the guest that do not depend on the persona.
    check("getconf CLK_TCK", s.run("getconf CLK_TCK").strip(), "100")
    check("getconf LONG_BIT", s.run("getconf LONG_BIT").strip(), "64")
    check("getconf PAGESIZE", s.run("getconf PAGESIZE").strip(), "4096")
    check("getconf OPEN_MAX", s.run("getconf OPEN_MAX").strip(), "1024")
    check("getconf CHAR_BIT", s.run("getconf CHAR_BIT").strip(), "8")
    check("getconf _POSIX_VERSION", s.run("getconf _POSIX_VERSION").strip(),
          "200809")
    check("getconf GNU_LIBC_VERSION",
          s.run("getconf GNU_LIBC_VERSION").strip(), "glibc 2.41")
    # A variable the platform does not define prints the word, not a blank.
    check("undefined prints 'undefined'",
          s.run("getconf TZNAME_MAX").strip(), "undefined")


def t_getconf_agrees_with_the_rest_of_the_box():
    """The cross-checks. This is the half that a table alone would miss."""
    s = sh()
    phys = num(s.run("getconf _PHYS_PAGES"))
    page = num(s.run("getconf PAGESIZE"))
    memtotal = num(s.run("grep MemTotal /proc/meminfo | awk '{print $2}'"))
    check("_PHYS_PAGES * PAGESIZE == MemTotal",
          (phys * page // 1024) if (phys and page) else phys, memtotal)

    avail = num(s.run("getconf _AVPHYS_PAGES"))
    memfree = num(s.run("grep ^MemFree /proc/meminfo | awk '{print $2}'"))
    check("_AVPHYS_PAGES * PAGESIZE == MemFree",
          (avail * page // 1024) if (avail and page) else avail, memfree)

    # getconf reports one cache instance; lscpu reports the total across
    # them. free(1)-style unit parsing, because lscpu prints KiB/MiB.
    ncpu = num(s.run("nproc")) or 1
    def lscpu_bytes(label):
        try:
            row = s.run("lscpu | grep '%s'" % label).strip()
            parts = row.split(":", 1)[1].split()
            val, unit = float(parts[0]), parts[1]
            mult = {"KiB": 1024, "MiB": 1024 ** 2, "GiB": 1024 ** 3}[unit]
            return int(val * mult)
        except Exception:                                      # noqa: BLE001
            return None
    for label, var, inst in (("L1d cache", "LEVEL1_DCACHE_SIZE", ncpu),
                             ("L1i cache", "LEVEL1_ICACHE_SIZE", ncpu),
                             ("L2 cache", "LEVEL2_CACHE_SIZE", ncpu),
                             ("L3 cache", "LEVEL3_CACHE_SIZE", 1)):
        got = num(s.run("getconf %s" % var))
        check("%s: lscpu total == getconf * instances" % label,
              lscpu_bytes(label), (got * inst) if got else got)


def t_getconf_error_behaviour():
    """Measured on the guest, including the rc."""
    s = sh()
    check("unrecognised variable rc",
          s.run("getconf BOGUS_XYZ >/dev/null 2>&1; echo $?").strip(), "2")
    check("unrecognised message",
          "Unrecognized variable" in s.run("getconf BOGUS_XYZ 2>&1"), True)
    check("no arguments rc",
          s.run("getconf >/dev/null 2>&1; echo $?").strip(), "2")
    check("usage mentions -a",
          "getconf -a [pathname]" in s.run("getconf 2>&1"), True)
    # pathconf variables need a pathname, but still appear in -a.
    check("NAME_MAX without a path is a usage error",
          s.run("getconf NAME_MAX >/dev/null 2>&1; echo $?").strip(), "2")
    check("NAME_MAX with a path answers",
          s.run("getconf NAME_MAX /tmp").strip(), "255")
    check("PATH_MAX with a path answers",
          s.run("getconf PATH_MAX /tmp").strip(), "4096")
    check("NAME_MAX is still listed by -a",
          any(l.startswith("NAME_MAX") for l in s.run("getconf -a").splitlines()),
          True)
    check("-v SPEC is accepted and ignored",
          s.run("getconf -v POSIX2008 PAGESIZE").strip(), "4096")


def t_psr_agrees_with_proc():
    """ps -eo psr said "-" while /proc/<pid>/stat field 39 said a number."""
    s = sh()
    check("ps psr is not a dash",
          "-" in s.run("ps -eo psr=").split(), False)
    seen = sorted(set(s.run("ps -eo psr=").split()))
    check("every psr is numeric", all(x.isdigit() for x in seen), True)
    ncpu = num(s.run("nproc")) or 1
    check("no psr exceeds the cpu count",
          all(x.isdigit() and 0 <= int(x) < ncpu for x in seen), True)
    # More than one CPU is in use -- a four-CPU box on which everything
    # runs on cpu0 is its own tell.
    check("processes are spread over more than one cpu", len(seen) > 1, True)
    # And the two readers agree, per pid.
    for pid in ("1", "3"):
        stat = s.run("cat /proc/%s/stat" % pid).split()
        if len(stat) > 38:
            check("ps psr == /proc/%s/stat field 39" % pid,
                  s.run("ps -o psr= -p %s" % pid).strip(), stat[38])


def t_the_gpu_questions_it_actually_asked():
    """The seven commands from 203.0.113.62, verbatim."""
    s = sh()
    check("lspci names a VGA device",
          s.run("lspci | grep VGA | cut -f5- -d ' '").strip() != "", True)
    check("VGA device count", s.run("lspci | grep VGA -c").strip(), "1")
    check("no 3D controller",
          s.run("lspci | grep '3D controller' | cut -f5- -d ' '").strip(), "")
    # nvidia-smi is not installed, and that is the right answer for a box
    # whose only display device is the QEMU one lspci reports.
    check("nvidia-smi is not found",
          s.run("nvidia-smi >/dev/null 2>&1; echo $?").strip(), "127")
    check("the pipeline it used yields nothing",
          s.run("nvidia-smi -q | grep 'Product Name' | head -n 1").strip(), "")
    check("...and its counting form yields 0",
          s.run("nvidia-smi -q | grep 'Product Name' | grep . -c").strip(), "0")
    check("uptime -p answers", s.run("uptime -p").startswith("up "), True)


def main():
    for fn in (t_cpu_count_agrees_everywhere,
               t_getconf_answers_at_all,
               t_getconf_agrees_with_the_rest_of_the_box,
               t_getconf_error_behaviour,
               t_psr_agrees_with_proc,
               t_the_gpu_questions_it_actually_asked):
        fn()
    for name, got, want in FAILS:
        print("  FAIL %-52s got %r want %r" % (name, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("hwprofiletest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
