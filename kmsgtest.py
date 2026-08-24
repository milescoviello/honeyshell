#!/usr/bin/env python3
"""Three commands read the kernel's messages. Do they agree?

`dmesg`, `journalctl -k` and /var/log/kern.log are three views of one ring
buffer on a real box. Here they were three separate inventions:

  - `dmesg` was eight hand-written lines. Every flag was accepted and
    ignored, so `dmesg -T` printed seconds-since-boot where every real one
    prints a date, `dmesg -x` printed no facility, and
    `dmesg --level=err` printed the whole buffer.
  - `journalctl -k` was not kernel-filtered at all: it printed CRON jobs and
    ssh logins, which no kernel has ever emitted. `journalctl -k | grep -i
    virtio` found nothing on a box whose `dmesg` had virtio lines and whose
    `lspci` lists virtio devices -- and "what am I running on" is the first
    thing a miner dropper asks.
  - /var/log/kern.log held exactly one line, and /var/log/syslog held a
    hand-written "SYN flooding on port 80" the ring buffer had never heard
    of -- computed from time.time(), so it moved every time anyone looked.
  - `rmmod evdev` left a message in dmesg that neither file ever saw.
  - `journalctl` as a non-root user answered "journalctl: /var/log/syslog:
    Permission denied", naming a file journalctl does not read. journald's
    files are root and group adm; a user in neither sees their own journal,
    which holds none of this.
  - logrotate was configured, five rotated copies existed, and there was no
    /var/lib/logrotate/status saying when it had last run.
  - `file /boot/vmlinuz-*` dated the kernel 2026-08-05 while `uname -v`,
    /proc/version and /proc/sys/kernel/version all said 2026-07-01.

One ring buffer now, rendered three ways, with the boot modelled on the
real Debian 13 cloud guest this box imitates (util-linux 2.41 dmesg) and
every value replaced by this persona's. Formats measured against that
guest's own dmesg -T/-x/-H/-t/--level.

Run from `honeypot/`, or on the guest.
"""

import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def sh(user="root"):
    s = fs.Shell(fs.VFS(), peer="203.0.113.77", user=user)
    s.exec_mode = True
    return s


def run(s, cmd):
    out = s.run(cmd)
    err = "".join(s._err)
    s._err.clear()
    return (out + err), s.last_rc


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-52s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


# --- one buffer, three readers ---------------------------------------------

def t_dmesg_and_journalctl_k_carry_the_same_messages():
    s = sh()
    d, _ = run(s, "dmesg -t")
    j, _ = run(s, "journalctl -k")
    dl = [l for l in d.splitlines() if l.strip()]
    jl = [l.split(" kernel: ", 1)[1] for l in j.splitlines()
          if " kernel: " in l]
    check("dmesg has a boot to show", len(dl) > 50, len(dl))
    eq("journalctl -k carries every line dmesg does", jl, dl)


def t_journalctl_k_is_kernel_only():
    s = sh()
    o, _ = run(s, "journalctl -k")
    for noise in ("sshd", "CRON", "systemd-logind", "nginx"):
        check("journalctl -k does not print %s lines" % noise,
              noise not in o, [l for l in o.splitlines() if noise in l][:1])
    check("and every line it does print is the kernel's",
          all(" kernel: " in l for l in o.splitlines()
              if l.strip() and not l.startswith("--")), o[:120])


def t_virtio_is_the_same_answer_everywhere():
    """What am I running on -- asked three ways."""
    s = sh()
    a, _ = run(s, "dmesg | grep -c virtio")
    b, _ = run(s, "journalctl -k | grep -c virtio")
    check("dmesg finds virtio in the ring buffer", int(a.strip()) >= 2, a)
    eq("journalctl -k finds exactly as many", b.strip(), a.strip())
    o, _ = run(s, "dmesg | grep -c 'Hypervisor detected: KVM'")
    eq("and the hypervisor line is in there once", o.strip(), "1")
    o2, _ = run(s, "systemd-detect-virt")
    eq("agreeing with systemd-detect-virt", o2.strip(), "kvm")


def t_the_first_line_is_proc_version():
    s = sh()
    d, _ = run(s, "dmesg -t | head -1")
    v, _ = run(s, "cat /proc/version")
    eq("dmesg's first line is exactly /proc/version", d.strip(), v.strip())
    c, _ = run(s, "dmesg -t | sed -n 2p")
    cl, _ = run(s, "cat /proc/cmdline")
    eq("and its second names the same command line",
       c.strip(), "Command line: " + cl.strip())


def t_the_kernel_image_agrees_with_the_running_kernel():
    s = sh()
    f, _ = run(s, "file /boot/vmlinuz-%s" % fs.KERNEL)
    u, _ = run(s, "uname -v")
    check("file's bzImage version matches uname -v",
          u.strip() in f, f[:160])
    p, _ = run(s, "cat /proc/sys/kernel/version")
    eq("and /proc/sys/kernel/version is the same string",
       p.strip(), u.strip())


def t_kern_log_is_the_ring_buffer_written_down():
    s = sh()
    k, _ = run(s, "cat /var/log/kern.log /var/log/kern.log.1")
    d, _ = run(s, "dmesg -t")
    seen = set(l.split(" kernel: ", 1)[1] for l in k.splitlines()
               if " kernel: " in l)
    check("the rotated kernel logs have content", seen, k[:80])
    missing = [m for m in seen if m not in d]
    eq("every line in them is in the ring buffer too", missing, [])


def t_the_boot_has_aged_out_of_the_files():
    """Weekly rotation keeping four, on a box that booted six weeks ago."""
    s = sh()
    k, _ = run(s, "cat /var/log/kern.log /var/log/kern.log.1")
    check("the boot is not in the current kern.log",
          "Linux version" not in k, k[:80])
    j, _ = run(s, "journalctl -k | head -2")
    check("but the journal still has it, as journald keeps its own",
          "Linux version" in j, j[:120])
    st, _ = run(s, "cat /var/lib/logrotate/status")
    check("and logrotate says when it last rotated the file",
          "/var/log/kern.log" in st, st[:120])
    m, _ = run(s, "stat -c %Y /var/log/kern.log")
    rot = re.search(r'"/var/log/kern\.log" (\S+)', st)
    if rot:
        when = time.mktime(time.strptime(rot.group(1),
                                         "%Y-%m-%d-%H:%M:%S"))
        check("the file is not older than its own rotation",
              int(m.strip()) >= int(when) - 1,
              "mtime %s rotated %s" % (m.strip(), int(when)))


def t_a_fresh_kernel_message_reaches_all_three():
    s = sh()
    run(s, "rmmod evdev")
    d, _ = run(s, "dmesg | tail -1")
    check("dmesg has it", "evdev" in d, d[:80])
    k, _ = run(s, "tail -1 /var/log/kern.log")
    check("rsyslog wrote it to kern.log", "evdev" in k, k[:80])
    y, _ = run(s, "grep -c evdev /var/log/syslog")
    eq("and to syslog, which this box routes *.* into", y.strip(), "1")
    j, _ = run(s, "journalctl -k | tail -1")
    check("and the journal has it", "evdev" in j, j[:80])


def t_the_log_does_not_move():
    s = sh()
    first, _ = run(s, "dmesg -t")
    real = time.time
    fs.time.time = lambda: real() + 7200
    try:
        later, _ = run(s, "dmesg -t")
    finally:
        fs.time.time = real
    a, b = first.splitlines(), later.splitlines()
    eq("two hours later the buffer says the same thing", b[:len(a)], a)


def t_syslog_holds_no_kernel_line_the_buffer_lacks():
    s = sh()
    y, _ = run(s, "grep ' kernel: ' /var/log/syslog")
    d, _ = run(s, "dmesg -t")
    for line in y.splitlines():
        msg = line.split(" kernel: ", 1)[1]
        check("syslog's kernel line is in the ring buffer: %s" % msg[:40],
              msg in d, msg[:70])


# --- dmesg's own flags, against util-linux 2.41 -----------------------------

def t_T_prints_dates():
    s = sh()
    o, _ = run(s, "dmesg -T | head -1")
    m = re.match(r"^\[([A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]\d "
                 r"\d\d:\d\d:\d\d \d{4})\] ", o)
    check("-T stamps with a ctime date, not seconds since boot",
          m is not None, o[:60])
    if m:
        when = time.mktime(time.strptime(m.group(1), "%a %b %d %H:%M:%S %Y"))
        check("and the first line is stamped at the boot",
              abs(when - fs.BOOT_TS) < 90,
              "%s vs %s" % (when, fs.BOOT_TS))


def t_x_decodes_facility_and_level():
    s = sh()
    o, _ = run(s, "dmesg -x | head -2")
    lines = o.splitlines()
    check("-x prefixes the facility and level",
          lines and lines[0].startswith("kern  :notice: ["), lines[:1])
    check("padded the way util-linux pads them",
          any(l.startswith("kern  :info  : [") for l in lines), lines[:2])
    e, _ = run(s, "dmesg -x --level=err | head -1")
    check("a userspace error is tagged daemon", e.startswith("daemon:err"),
          e[:40])


def t_level_filters():
    s = sh()
    all_, _ = run(s, "dmesg")
    err, _ = run(s, "dmesg --level=err")
    warn, _ = run(s, "dmesg --level=warn")
    both, _ = run(s, "dmesg --level=err,warn")
    n = len(all_.splitlines())
    check("--level=err is a subset", 0 < len(err.splitlines()) < n,
          len(err.splitlines()))
    check("--level=warn is a subset", 0 < len(warn.splitlines()) < n,
          len(warn.splitlines()))
    eq("and the two together are the sum",
       len(both.splitlines()),
       len(err.splitlines()) + len(warn.splitlines()))
    o, rc = run(s, "dmesg --level=nosuchlevel")
    eq("an unknown level is an error", rc, 1)
    check("named in the message", "unknown level" in o, o[:60])


def t_k_and_u_split_the_buffer():
    s = sh()
    a, _ = run(s, "dmesg")
    k, _ = run(s, "dmesg -k")
    u, _ = run(s, "dmesg -u")
    eq("kernel plus userspace is the whole buffer",
       len(k.splitlines()) + len(u.splitlines()), len(a.splitlines()))
    check("there is some of each", k.splitlines() and u.splitlines(),
          (len(k.splitlines()), len(u.splitlines())))


def t_t_drops_the_timestamps():
    s = sh()
    o, _ = run(s, "dmesg -t | head -3")
    check("-t prints no bracket at all",
          not any(l.startswith("[") for l in o.splitlines()), o[:60])


def t_H_is_relative_under_a_minute_header():
    s = sh()
    o, _ = run(s, "dmesg -H | head -3")
    lines = o.splitlines()
    check("-H opens with a month-day-time header",
          re.match(r"^\[[A-Z][a-z]{2}\d\d \d\d:\d\d\] ", lines[0])
          is not None, lines[0][:40])
    check("and continues with signed deltas",
          all(re.match(r"^\[ *\+\d+\.\d{6}\] ", l) for l in lines[1:]),
          lines[1:2])


def t_clearing_the_buffer_leaves_the_files():
    s = sh()
    before, _ = run(s, "dmesg | wc -l")
    check("there is a buffer to clear", int(before.strip()) > 50, before)
    o, rc = run(s, "dmesg -C")
    eq("dmesg -C rc", rc, 0)
    eq("and prints nothing", o.strip(), "")
    after, _ = run(s, "dmesg | wc -l")
    eq("the ring buffer is empty afterwards", after.strip(), "0")
    j, _ = run(s, "journalctl -k | grep -c 'Linux version'")
    eq("but the journal kept its copy", j.strip(), "1")
    k, _ = run(s, "cat /var/log/kern.log.1 | wc -l")
    check("and so did the rotated file", int(k.strip()) > 0, k)


def t_read_clear_prints_then_clears():
    s = sh()
    o, rc = run(s, "dmesg -c")
    eq("dmesg -c rc", rc, 0)
    check("-c prints the buffer", "Linux version" in o, o[:60])
    after, _ = run(s, "dmesg | wc -l")
    eq("and then it is gone", after.strip(), "0")


def t_dmesg_restrict_is_honoured():
    s = sh()
    d = sh(user="deploy")
    o, rc = run(d, "dmesg | head -1")
    eq("with dmesg_restrict 0 a normal user may read", rc, 0)
    check("and gets the buffer", "Linux version" in o, o[:60])
    run(s, "sysctl -w kernel.dmesg_restrict=1")
    v, _ = run(s, "cat /proc/sys/kernel/dmesg_restrict")
    if v.strip() == "1":
        d2 = fs.Shell(s.fs, peer="203.0.113.77", user="deploy")
        d2.exec_mode = True
        o2, rc2 = run(d2, "dmesg")
        eq("once it is 1 the same read fails", rc2, 1)
        check("with the kernel's wording",
              "Operation not permitted" in o2, o2[:80])
        o3, rc3 = run(s, "dmesg | wc -l")
        check("root still reads it", int(o3.strip()) > 50, o3)


def t_a_non_root_journalctl_names_no_files():
    d = sh(user="deploy")
    o, _ = run(d, "journalctl -k")
    check("it does not name /var/log/syslog",
          "/var/log/syslog" not in o, o[:80])
    check("it answers the way journald does",
          "No entries" in o or "No journal files" in o, o[:80])


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("t_")]


def main():
    for t in TESTS:
        try:
            t()
        except Exception as exc:                              # noqa: BLE001
            check(t.__name__, False, "crashed: %r" % (exc,))
    print("passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
