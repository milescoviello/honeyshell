#!/usr/bin/env python3
"""Does systemd agree with itself about what starts at boot?

Previous sweeps checked the edges of this -- is-active against ps, MainPID,
whether stopping a unit removes its socket -- but never the unit files or
the enablement symlinks. Those matter twice over: `ls /etc/systemd/system/
*.wants/` is how anyone checks what starts at boot, and it is where systemd
persistence gets planted.

What it found:

  - /etc/systemd/system/multi-user.target.wants/ contained exactly one
    symlink, ssh.service, while nginx, mariadb, cron, rsyslog and
    php8.4-fpm all reported "enabled". The symlink *is* the enablement, so
    `systemctl is-enabled` and the directory disagreed about five services.
  - is-enabled returned "enabled" for anything in the unit table, so it
    could not have said otherwise. It now derives: no [Install] means
    static, otherwise the answer is whether the symlink exists.
  - Every unit file carried an [Install] section, including
    systemd-journald, systemd-logind and dbus. Measured on the guest, all
    three are "static" there -- a static unit has no [Install] at all, which
    is exactly why it cannot be enabled.
  - systemctl enable/disable set a state flag and left the symlink alone,
    so a disabled unit still had its link sitting in the wants directory.
    They now create and remove it, and say so in systemd's own wording.
  - getty@tty1 reported not-found, because the unit file is the template
    getty@.service. agetty is in ps on tty1, so the instance has to resolve.

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []
WANTS = "/etc/systemd/system/multi-user.target.wants"
LIB = "/usr/lib/systemd/system"


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
        print("  FAIL %-52s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


ENABLED = ("nginx", "mariadb", "ssh", "cron", "rsyslog", "php8.4-fpm")
STATIC = ("systemd-journald", "systemd-logind", "dbus")


def t_enabled_units_have_their_symlink():
    """The disagreement this sweep started from."""
    s = sh()
    for u in ENABLED:
        o, _ = run(s, "systemctl is-enabled %s" % u)
        eq("%s is enabled" % u, o.strip(), "enabled")
        o2, rc = run(s, "test -L %s/%s.service && echo ok" % (WANTS, u))
        eq("...and has a wants symlink" + (" (%s)" % u),
           (o2.strip(), rc), ("ok", 0))
        o3, _ = run(s, "readlink %s/%s.service" % (WANTS, u))
        eq("...pointing at its unit file (%s)" % u, o3.strip(),
           "%s/%s.service" % (LIB, u))


def t_static_units_are_static():
    s = sh()
    for u in STATIC:
        o, _ = run(s, "systemctl is-enabled %s" % u)
        eq("%s is static, not enabled" % u, o.strip(), "static")
        o2, rc = run(s, "test -e %s/%s.service && echo present" % (WANTS, u))
        check("%s has no wants symlink" % u, rc != 0, "symlink present")
        # ...because its unit file has no [Install] section.
        o3, _ = run(s, "grep -c '\\[Install\\]' %s/%s.service" % (LIB, u))
        eq("%s unit file has no [Install]" % u, o3.strip(), "0")


def t_every_enabled_unit_file_declares_where():
    s = sh()
    for u in ENABLED:
        o, _ = run(s, "grep -c '\\[Install\\]' %s/%s.service" % (LIB, u))
        eq("%s declares [Install]" % u, o.strip(), "1")
        o2, _ = run(s, "grep WantedBy %s/%s.service" % (LIB, u))
        check("%s says WantedBy=multi-user.target" % u,
              "multi-user.target" in o2, o2[:60])


def t_wants_directory_has_no_orphans():
    """A symlink to a unit file that does not exist would be visible."""
    s = sh()
    o, _ = run(s, "ls %s" % WANTS)
    names = [n for n in o.split() if n.endswith(".service")]
    check("the wants directory is populated", len(names) >= 6, str(names))
    for n in names:
        tgt, _ = run(s, "readlink %s/%s" % (WANTS, n))
        o2, rc = run(s, "test -f %s && echo ok" % tgt.strip())
        eq("%s points at a real unit file" % n, (o2.strip(), rc), ("ok", 0))


def t_running_services_are_enabled():
    """Everything in ps that has a unit should start at boot."""
    s = sh()
    for u in ENABLED:
        o, _ = run(s, "systemctl is-active %s" % u)
        if o.strip() != "active":
            continue
        o2, _ = run(s, "systemctl is-enabled %s" % u)
        eq("%s is active, so it must be enabled" % u, o2.strip(), "enabled")


def t_systemctl_cat_matches_the_file_on_disk():
    s = sh()
    for u in ("nginx", "rsyslog"):
        o, rc = run(s, "systemctl cat %s" % u)
        eq("systemctl cat %s works" % u, rc, 0)
        check("it names the path it read", "%s/%s.service" % (LIB, u) in o,
              o[:70])
        body, _ = run(s, "cat %s/%s.service" % (LIB, u))
        for line in body.splitlines():
            if line.strip().startswith("ExecStart="):
                check("cat and the file agree on ExecStart (%s)" % u,
                      line.strip() in o, line[:60])
                break


def t_execstart_points_at_a_real_binary():
    """A unit whose ExecStart does not exist could never have started."""
    s = sh()
    o, _ = run(s, "ls %s" % LIB)
    for unit in [n for n in o.split() if n.endswith(".service")]:
        body, _ = run(s, "grep ExecStart %s/%s" % (LIB, unit))
        for line in body.splitlines():
            if "=" not in line:
                continue
            exe = line.split("=", 1)[1].strip().lstrip("-+!@").split()[0]
            if not exe.startswith("/") or "%" in exe:
                continue
            o2, rc = run(s, "test -e %s && echo ok" % exe)
            eq("%s ExecStart %s exists" % (unit, exe), (o2.strip(), rc),
               ("ok", 0))


def t_template_instances_resolve():
    s = sh()
    o, _ = run(s, "systemctl is-enabled getty@tty1")
    eq("getty@tty1 resolves to its template", o.strip(), "enabled")
    o2, rc = run(s, "test -L /etc/systemd/system/getty.target.wants/"
                    "getty@tty1.service && echo ok")
    eq("and has its symlink", (o2.strip(), rc), ("ok", 0))
    # agetty is in ps on tty1, which is what that unit runs.
    o3, _ = run(s, "ps -eo args --no-headers")
    check("agetty is running on tty1",
          "agetty" in o3 and "tty1" in o3, "not running")


def t_unknown_unit_is_not_found():
    s = sh()
    o, _ = run(s, "systemctl is-enabled definitely-not-a-unit")
    eq("an unknown unit is not-found", o.strip(), "not-found")


def t_enable_and_disable_move_the_symlink():
    """They set a flag and left the link in place."""
    s = sh()
    o, _ = run(s, "systemctl disable nginx")
    check("disable says what it removed", "Removed" in o and WANTS in o,
          o[:90])
    o2, rc = run(s, "test -e %s/nginx.service && echo present" % WANTS)
    check("the symlink is gone", rc != 0, "still there")
    o3, _ = run(s, "systemctl is-enabled nginx")
    eq("and is-enabled agrees", o3.strip(), "disabled")

    o4, _ = run(s, "systemctl enable nginx")
    check("enable says what it created", "Created symlink" in o4, o4[:90])
    o5, rc5 = run(s, "test -L %s/nginx.service && echo ok" % WANTS)
    eq("the symlink is back", (o5.strip(), rc5), ("ok", 0))
    o6, _ = run(s, "systemctl is-enabled nginx")
    eq("and is-enabled agrees again", o6.strip(), "enabled")
    # The unit file itself must survive the round trip: getting symlink's
    # argument order backwards replaced it with a link into the wants dir.
    o7, _ = run(s, "stat -c %F " + LIB + "/nginx.service")
    eq("the unit file is still a regular file", o7.strip(), "regular file")
    o8, _ = run(s, "readlink %s/nginx.service" % WANTS)
    eq("and the link points the right way", o8.strip(),
       "%s/nginx.service" % LIB)


def t_disable_survives_a_reread():
    """The state must live in the filesystem, not only in memory."""
    s = sh()
    run(s, "systemctl disable rsyslog")
    o, _ = run(s, "ls %s" % WANTS)
    check("rsyslog is gone from the wants listing",
          "rsyslog.service" not in o.split(), o[:80])
    o2, _ = run(s, "systemctl is-enabled rsyslog")
    eq("is-enabled reads it back as disabled", o2.strip(), "disabled")


TESTS = [t_enabled_units_have_their_symlink, t_static_units_are_static,
         t_every_enabled_unit_file_declares_where,
         t_wants_directory_has_no_orphans, t_running_services_are_enabled,
         t_systemctl_cat_matches_the_file_on_disk,
         t_execstart_points_at_a_real_binary, t_template_instances_resolve,
         t_unknown_unit_is_not_found, t_enable_and_disable_move_the_symlink,
         t_disable_survives_a_reread]


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
