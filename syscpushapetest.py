#!/usr/bin/env python3
"""Is /sys/devices/system/cpu the shape a real machine's is?

Every number under here was right and the *shape* was wrong. `ls
/sys/devices/system/cpu/` on a real KVM guest lists thirteen entries this
box did not have, and one of them matters on its own: `cat
/sys/devices/system/cpu/smt/active` is the stock way to ask whether SMT is
on, and it answered "No such file or directory" while `lscpu`, one command
away, reported "Thread(s) per core: 2". A box that admits to SMT in one
place and denies the file exists in another has answered one question
twice.

`/sys/devices/system/cpu/cpufreq` is the sharpest of the rest, because it
is not a missing value but a missing *distinction*. On a KVM guest that
directory exists and is empty -- there is no governor to expose -- so

    test -d /sys/devices/system/cpu/cpufreq          -> true
    test -d /sys/devices/system/cpu/cpufreq/policy0  -> false

and we were on the wrong side of the first one. An empty directory and a
missing one are one `test -d` apart.

And the opposite error: we *had* /sys/devices/system/cpu/cpu0/online. A
real x86 box does not. The boot CPU cannot be taken offline, so the kernel
never creates the attribute -- cpu0 carries cache, cpu_capacity,
crash_notes, crash_notes_size, driver, firmware_node, hotplug, node0,
power, subsystem, topology and uevent, and no `online`. Every other cpuN
has one. Writing it for all 64 was a uniformity a real box does not have.

The values here were read byte for byte off a live KVM guest, not invented,
which matters for the ones nobody would guess: `isolated` and `offline` are
a bare newline rather than an empty file, and `nohz_full` is fourteen
spaces followed by "(null)" because the kernel formats it into a
fixed-width field.

Two things were deliberately NOT copied from that reference, because
copying them would have been worse than the gap:

  * `umwait_control` is an Intel feature. The reference box is Intel; this
    persona is a Threadripper. An AMD box with an Intel-only sysfs knob is
    a louder tell than one missing knob.
  * `smt/active` reads 0 and `smt/control` "notsupported" on the reference,
    which has SMT off. Copying that would have contradicted our own
    topology, which is the exact failure this suite exists to catch. We say
    1 and "on", because we claim two threads per core everywhere else.

Still outstanding and deliberately not faked: `modalias` and the per-cpu
`uevent`, both of which embed the x86 capability bitmap. Reproducing that
for a Zen 4 part means the real X86_FEATURE indices, and every machine
available to measure from is Intel. A wrong bitmap on an AMD box is worse
than an absent file, so they are left out and written down here.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fakeshell

CHECKS, FAILS = [], []


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want, "\n  -- " + note if note else ""))


def shell():
    return fakeshell.Shell(vfs=fakeshell.VFS(), peer="198.51.100.13",
                           peer_port=40333)


def out(sh, cmd):
    return (sh.run(cmd) or "").strip()


def main():
    sh = shell()
    B = "/sys/devices/system/cpu"

    # -- the distinction between empty and absent -------------------------
    check("cpufreq exists", out(sh, "test -d %s/cpufreq && echo D || echo N" % B), "D",
          "a KVM guest has the directory; it is empty, not missing")
    check("cpufreq is empty", out(sh, "ls %s/cpufreq | wc -l" % B), "0")
    check("listing it succeeds", out(sh, "ls %s/cpufreq >/dev/null 2>&1; echo $?" % B), "0")
    check("but there is no policy0",
          out(sh, "test -d %s/cpufreq/policy0 && echo D || echo N" % B), "N",
          "there is no governor on a guest, so no policy directory")
    check("and no per-cpu cpufreq",
          out(sh, "test -d %s/cpu0/cpufreq && echo D || echo N" % B), "N")

    # -- the one that contradicted lscpu ----------------------------------
    check("smt/active says SMT is on", out(sh, "cat %s/smt/active" % B), "1")
    check("smt/control says on", out(sh, "cat %s/smt/control" % B), "on")
    threads = [l for l in (sh.run("lscpu") or "").splitlines()
               if l.startswith("Thread(s) per core")]
    check("lscpu still agrees SMT is on",
          bool(threads) and threads[0].split(":")[1].strip(), "2",
          "smt/active and lscpu are the same fact")

    # -- cpu0 has no `online`, every other cpu does -----------------------
    check("cpu0 has no online attribute",
          out(sh, "test -e %s/cpu0/online && echo Y || echo N" % B), "N",
          "the boot CPU cannot be offlined, so the kernel never creates it")
    for c in (1, 7, fakeshell.NCPU - 1):
        check("cpu%d does have one" % c,
              out(sh, "test -e %s/cpu%d/online && echo Y || echo N" % (B, c)), "Y")
    check("cpu0 still carries the rest",
          out(sh, "test -e %s/cpu0/cpu_capacity && test -d %s/cpu0/topology "
                  "&& echo Y || echo N" % (B, B)), "Y")

    # -- values, byte for byte off the reference --------------------------
    check("enabled tracks online", out(sh, "cat %s/enabled" % B),
          "0-%d" % (fakeshell.NCPU - 1))
    check("online agrees", out(sh, "cat %s/online" % B),
          "0-%d" % (fakeshell.NCPU - 1))
    check("crash_hotplug", out(sh, "cat %s/crash_hotplug" % B), "0")
    check("cpu_capacity", out(sh, "cat %s/cpu0/cpu_capacity" % B), "1024")
    check("cpuidle driver", out(sh, "cat %s/cpuidle/current_driver" % B), "none")
    check("cpuidle governor", out(sh, "cat %s/cpuidle/current_governor" % B), "menu")
    check("cpuidle governors",
          out(sh, "cat %s/cpuidle/available_governors" % B),
          "ladder menu teo haltpoll")
    check("power/control", out(sh, "cat %s/power/control" % B), "auto")
    check("power/runtime_status",
          out(sh, "cat %s/power/runtime_status" % B), "unsupported")

    # The whitespace nobody would guess, which is why it was measured.
    raw = sh.fs.read("%s/nohz_full" % B)
    if isinstance(raw, bytes):
        raw = raw.decode("latin-1")
    check("nohz_full is padded into a fixed-width field",
          raw, " " * 14 + "(null)\n")
    for f in ("isolated", "offline"):
        raw = sh.fs.read("%s/%s" % (B, f))
        if isinstance(raw, bytes):
            raw = raw.decode("latin-1")
        check("%s is a bare newline, not an empty file" % f, raw, "\n")

    # -- and the Intel knob we did not copy -------------------------------
    check("no umwait_control on an AMD part",
          out(sh, "test -e %s/umwait_control && echo Y || echo N" % B), "N",
          "Intel-only; copying it from the reference box would be a tell")

    print("%d/%d assertions pass" % (sum(CHECKS), len(CHECKS)))
    for f in FAILS:
        print(f)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
