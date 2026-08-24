#!/usr/bin/env python3
"""Does sysctl agree with /proc/sys?

sysctl *is* /proc/sys -- the tool does nothing but read and write files under
that directory. So it is a pure two-views-of-one-fact question, and the two
views disagreed about 19 of 27 keys.

  - `cat /proc/sys/kernel/version` printed the version while
    `sysctl kernel.version` answered "cannot stat
    /proc/sys/kernel/version: No such file or directory" -- naming, as
    missing, the exact file the other command had just read. sysctl carried
    its own dict of eight settings and never looked at the tree.
  - `sysctl -a` reported 8 keys where the tree held 27, and could not grow.
  - -n was ignored, so `v=$(sysctl -n kernel.osrelease)` captured
    "kernel.osrelease = 6.12.101+deb13-cloud-amd64" instead of the version.
    That is the worst shape of this bug: the command succeeds, the variable
    is populated, and everything downstream is quietly wrong.
  - `sysctl -w` echoed the assignment without storing it, so a re-read
    contradicted the command that had just reported success. Turning
    ip_forward on is a lateral-movement step, and someone checks.
  - kernel.yama.ptrace_scope said 1, which is Ubuntu's default. The guest
    reports 0, and an exploit reads this to decide whether ptrace injection
    is worth attempting.

sysctl now reads and writes the tree, so there is one source of truth and
`sysctl -a` grows as the tree does. Values are measured on the guest.

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def sh():
    s = fs.Shell(fs.VFS(), peer="203.0.113.77")
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
        print("  FAIL %-50s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


def tree_keys(s):
    return sorted(p[len("/proc/sys/"):].replace("/", ".")
                  for p in s.fs.nodes
                  if p.startswith("/proc/sys/") and not s.fs.isdir(p))


def t_every_proc_sys_file_is_readable_by_sysctl():
    """The disagreement this sweep started from: 19 of 27 keys."""
    s = sh()
    keys = tree_keys(s)
    check("the tree has a meaningful number of keys", len(keys) > 40,
          str(len(keys)))
    missing = []
    for k in keys:
        out, rc = run(s, "sysctl -n %s" % k)
        if rc != 0 or "cannot stat" in out:
            missing.append(k)
    eq("sysctl can read every file in /proc/sys", missing, [])


def t_sysctl_and_cat_return_the_same_bytes():
    s = sh()
    for k in ("kernel.osrelease", "kernel.version", "kernel.ostype",
              "kernel.hostname", "kernel.randomize_va_space",
              "vm.swappiness", "net.ipv4.ip_forward",
              "kernel.yama.ptrace_scope", "fs.protected_hardlinks"):
        a, _ = run(s, "sysctl -n %s" % k)
        b, _ = run(s, "cat /proc/sys/%s" % k.replace(".", "/"))
        eq("sysctl -n and cat agree on %s" % k, a.strip(), b.strip())


def t_dash_n_prints_only_the_value():
    """A substitution that silently poisons whatever consumes it."""
    s = sh()
    out, _ = run(s, "sysctl -n kernel.osrelease")
    check("-n omits the key", "=" not in out, out.strip()[:60])
    eq("-n gives the bare version", out.strip(), fs.KERNEL)
    out2, _ = run(s, "sysctl kernel.osrelease")
    check("without -n the key is present",
          out2.strip() == "kernel.osrelease = " + fs.KERNEL, out2.strip()[:70])
    # The shape a script actually uses.
    out3, _ = run(s, 'v=$(sysctl -n kernel.osrelease); echo "[$v]"')
    eq("command substitution captures the value", out3.strip(),
       "[%s]" % fs.KERNEL)


def t_dash_a_lists_the_whole_tree():
    s = sh()
    out, rc = run(s, "sysctl -a")
    eq("sysctl -a succeeds", rc, 0)
    lines = [l for l in out.splitlines() if " = " in l]
    keys = tree_keys(s)
    check("it lists roughly the tree, not a fixed handful",
          len(lines) >= len(keys) - 5,
          "%d lines for %d keys" % (len(lines), len(keys)))
    check("every line is key = value",
          all(" = " in l for l in out.splitlines() if l.strip()), out[:70])
    for k in ("kernel.version", "vm.swappiness", "net.core.somaxconn"):
        check("-a includes %s" % k, any(l.startswith(k + " =")
                                        for l in lines), "absent")


def t_write_persists():
    """Echoing an assignment without storing it contradicts the next read."""
    s = sh()
    before, _ = run(s, "cat /proc/sys/net/ipv4/ip_forward")
    eq("ip_forward starts at 0", before.strip(), "0")
    out, rc = run(s, "sysctl -w net.ipv4.ip_forward=1")
    eq("the write succeeds", rc, 0)
    eq("and echoes as sysctl does", out.strip(), "net.ipv4.ip_forward = 1")
    after, _ = run(s, "cat /proc/sys/net/ipv4/ip_forward")
    eq("the file changed", after.strip(), "1")
    again, _ = run(s, "sysctl -n net.ipv4.ip_forward")
    eq("and sysctl reads it back", again.strip(), "1")
    # Writing through /proc directly must be visible to sysctl too.
    run(s, "echo 0 > /proc/sys/net/ipv4/ip_forward")
    o, _ = run(s, "sysctl -n net.ipv4.ip_forward")
    eq("a direct /proc write is visible to sysctl", o.strip(), "0")


def t_unknown_key_fails_like_sysctl():
    s = sh()
    out, rc = run(s, "sysctl -n definitely.not.a.key")
    check("an unknown key fails", rc != 0, "rc=%s" % rc)
    check("with sysctl's own wording",
          "cannot stat /proc/sys/definitely/not/a/key" in out, out[:80])
    check("and mentions No such file or directory",
          "No such file or directory" in out, out[:80])


def t_the_values_an_exploit_reads():
    """These four decide what a local exploit will even attempt."""
    s = sh()
    for k, want in (("kernel.randomize_va_space", "2"),
                    ("kernel.perf_event_paranoid", "3"),
                    ("kernel.unprivileged_bpf_disabled", "2"),
                    ("kernel.yama.ptrace_scope", "0"),
                    ("user.max_user_namespaces", "0"),
                    ("vm.mmap_min_addr", "65536")):
        out, rc = run(s, "sysctl -n %s" % k)
        eq("%s is %s, as on the guest" % (k, want), (out.strip(), rc),
           (want, 0))


def t_kernel_identity_agrees_with_uname():
    """Three spellings of the same fact."""
    s = sh()
    a, _ = run(s, "sysctl -n kernel.osrelease")
    b, _ = run(s, "uname -r")
    eq("kernel.osrelease matches uname -r", a.strip(), b.strip())
    c, _ = run(s, "sysctl -n kernel.version")
    d, _ = run(s, "uname -v")
    eq("kernel.version matches uname -v", c.strip(), d.strip())
    e, _ = run(s, "sysctl -n kernel.ostype")
    f, _ = run(s, "uname -s")
    eq("kernel.ostype matches uname -s", e.strip(), f.strip())
    g, _ = run(s, "sysctl -n kernel.hostname")
    h, _ = run(s, "hostname")
    eq("kernel.hostname matches hostname", g.strip(), h.strip())


def t_tab_separated_values_survive():
    """tcp_rmem and printk are tab-separated triples/quads."""
    s = sh()
    for k in ("net.ipv4.tcp_rmem", "net.ipv4.tcp_wmem", "kernel.printk"):
        out, rc = run(s, "sysctl -n %s" % k)
        if rc != 0:
            continue
        check("%s has multiple fields" % k, len(out.split()) >= 3,
              repr(out.strip()))
        b, _ = run(s, "cat /proc/sys/%s" % k.replace(".", "/"))
        eq("%s matches the file" % k, out.split(), b.split())


def t_quiet_flag():
    s = sh()
    out, rc = run(s, "sysctl -q -w vm.swappiness=60")
    eq("-q writes silently", (out.strip(), rc), ("", 0))
    o, _ = run(s, "sysctl -n vm.swappiness")
    eq("but the value took", o.strip(), "60")


TESTS = [t_every_proc_sys_file_is_readable_by_sysctl,
         t_sysctl_and_cat_return_the_same_bytes,
         t_dash_n_prints_only_the_value, t_dash_a_lists_the_whole_tree,
         t_write_persists, t_unknown_key_fails_like_sysctl,
         t_the_values_an_exploit_reads, t_kernel_identity_agrees_with_uname,
         t_tab_separated_values_survive, t_quiet_flag]


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
