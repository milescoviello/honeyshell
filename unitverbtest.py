#!/usr/bin/env python3
"""What systemctl says when an attacker installs, enables and masks units.

203.0.113.33 dropped /etc/systemd/system/srbminer.service on 2026-08-25 and
ran `daemon-reexec`, `daemon-reload`, `enable`, `restart`. That sequence is
the load-bearing part of a persistence install, and the box has to hold up
under it -- both in what it *says* and in whether its answers agree
afterwards.

The eight unit verbs had **one** failure message between them:

    Failed to <verb> X.service: Unit X.service not found.    rc 5

Measured on the guest, that is right for three of eight:

    start / restart / reload   rc 5   "... not found."
    stop                       rc 5   "... not loaded."
    enable / disable           rc 1   "Failed to <verb> unit: Unit X
                                       does not exist"
    mask                       rc 0   proceeds anyway, and symlinks the
                                       name to /dev/null
    unmask                     rc 0   removes it

The rc is the part that bites: `systemctl enable X || fallback` branches on
it, and 5 where the real one gives 1 sends a script down the wrong path.
mask succeeding on a name that is not a unit is real behaviour and a real
technique -- it is how you stop a service starting without touching its
files.

Also `systemctl show X -p MainPID --value`, which ignored --value and
printed "MainPID=412" where the whole point of the flag is to get a bare
pid, and `Created symlink ... -> ...` which uses "->" where systemd prints
U+2192 (measured as the bytes e2 86 92).

Every expectation here was measured against the guest's own systemd, using
`--root` on a throwaway tree for the enable/disable cases so nothing live
was touched.

Usage:  python3 unitverbtest.py
"""

import sys

import fakeshell as F

CHECKS, FAILS = [], []

#: (rc, stderr lines) per verb for a name that is not a unit. Measured.
UNKNOWN = {
    "start":   ("5", ["Failed to start nosuchunit123.service: "
                      "Unit nosuchunit123.service not found."]),
    "stop":    ("5", ["Failed to stop nosuchunit123.service: "
                      "Unit nosuchunit123.service not loaded."]),
    "restart": ("5", ["Failed to restart nosuchunit123.service: "
                      "Unit nosuchunit123.service not found."]),
    "reload":  ("5", ["Failed to reload nosuchunit123.service: "
                      "Unit nosuchunit123.service not found."]),
    "enable":  ("1", ["Failed to enable unit: "
                      "Unit nosuchunit123.service does not exist"]),
    "disable": ("1", ["Failed to disable unit: "
                      "Unit nosuchunit123.service does not exist"]),
}


def check(name, got, want):
    CHECKS.append(name)
    if got != want:
        FAILS.append((name, got, want))


def sh(vfs=None):
    return F.Shell(vfs=vfs) if vfs is not None else F.Shell()


UNIT = ("[Unit]\n"
        "Description=SRBMiner Dual Mining Service\n"
        "After=network.target\n"
        "\n[Service]\n"
        "Type=simple\n"
        "ExecStart=/opt/srbminer/kaudit --config /opt/srbminer/cfg.txt\n"
        "Restart=always\n"
        "\n[Install]\n"
        "WantedBy=multi-user.target\n")


def install_unit(s, name="srbminer"):
    s.run("mkdir -p /opt/srbminer; echo x > /opt/srbminer/kaudit; "
          "chmod +x /opt/srbminer/kaudit")
    s.run("cat > /etc/systemd/system/%s.service <<'XEOF'\n%s\nXEOF"
          % (name, UNIT))
    return name


def t_unknown_unit_per_verb():
    """One message for eight verbs was wrong for five of them."""
    for verb, (rc, lines) in sorted(UNKNOWN.items()):
        s = sh()
        got_rc = s.run("systemctl %s nosuchunit123.service >/dev/null 2>&1; "
                       "echo $?" % verb).strip()
        got = [l for l in
               s.run("systemctl %s nosuchunit123.service 2>&1" % verb)
               .splitlines() if l.strip()]
        check("%s: rc" % verb, got_rc, rc)
        check("%s: message" % verb, got, lines)


def t_mask_proceeds_on_a_name_that_is_not_a_unit():
    s = sh()
    out = [l for l in s.run("systemctl mask nosuchunit123.service 2>&1")
           .splitlines() if l.strip()]
    check("mask says it is proceeding anyway",
          out[0] if out else None,
          "Unit nosuchunit123.service does not exist, proceeding anyway.")
    check("mask narrates the symlink, with systemd's arrow",
          out[1] if len(out) > 1 else None,
          "Created symlink '/etc/systemd/system/nosuchunit123.service' "
          "→ '/dev/null'.")
    check("mask succeeds",
          s.run("systemctl mask other999.service >/dev/null 2>&1; echo $?")
          .strip(), "0")
    # And it really is a symlink to /dev/null, not a note in a dict.
    check("the mask symlink points at /dev/null",
          s.run("readlink /etc/systemd/system/nosuchunit123.service").strip(),
          "/dev/null")


def t_unmask_depends_on_whether_anything_is_there():
    """After a mask it prints Removed; on a never-masked name, the notice."""
    s = sh()
    s.run("systemctl mask nosuchunit123.service")
    after = [l for l in s.run("systemctl unmask nosuchunit123.service 2>&1")
             .splitlines() if l.strip()]
    check("unmask after mask prints only Removed", after,
          ["Removed '/etc/systemd/system/nosuchunit123.service'."])
    check("...and the symlink is gone",
          s.run("test -e /etc/systemd/system/nosuchunit123.service; echo $?")
          .strip(), "1")
    fresh = sh()
    only = [l for l in fresh.run("systemctl unmask never999.service 2>&1")
            .splitlines() if l.strip()]
    check("unmask on a never-masked name prints only the notice", only,
          ["Unit never999.service does not exist, proceeding anyway."])


def t_show_value_prints_the_value():
    s = sh()
    # Stated as relations rather than by deriving the expectation from the
    # thing under test: the first version built "want" out of the --value
    # output, so against a build where --value was ignored it failed with
    # want 'MainPID=MainPID=412', which is true but unreadable.
    named = s.run("systemctl show ssh -p MainPID").strip()
    val = s.run("systemctl show ssh -p MainPID --value").strip()
    check("without --value the name is there", named.startswith("MainPID="),
          True)
    check("with --value there is no name at all", "=" in val, False)
    check("with --value it is a bare number", val.isdigit(), True)
    check("and it is the same number",
          named.split("=", 1)[1] if "=" in named else None, val)
    check("two properties, two bare values",
          s.run("systemctl show ssh -p MainPID -p ActiveState --value")
          .split(), [val, "active"])
    check("two properties without --value keep their names",
          s.run("systemctl show ssh -p MainPID -p ActiveState").split(),
          ["MainPID=%s" % val, "ActiveState=active"])


def t_enable_narrates_the_symlink():
    s = sh()
    name = install_unit(s)
    first = [l for l in s.run("systemctl enable %s.service 2>&1" % name)
             .splitlines() if l.strip()]
    check("enable prints one line", len(first), 1)
    if first:
        check("it is the Created symlink line, with U+2192",
              first[0].startswith("Created symlink '") and "→" in first[0],
              True)
        check("...and names the wants link",
              "/etc/systemd/system/multi-user.target.wants/%s.service" % name
              in first[0], True)
    check("enabling again is quiet",
          s.run("systemctl enable %s.service 2>&1" % name).strip(), "")
    off = [l for l in s.run("systemctl disable %s.service 2>&1" % name)
           .splitlines() if l.strip()]
    check("disable prints Removed", len(off) == 1
          and off[0].startswith("Removed '"), True)


def t_the_install_sequence_agrees_with_itself():
    """The cross-reader check: after enable+restart, do they all concur?"""
    s = sh()
    name = install_unit(s)
    s.run("systemctl daemon-reload")
    s.run("systemctl enable %s.service" % name)
    s.run("systemctl restart %s.service" % name)

    check("is-active", s.run("systemctl is-active %s" % name).strip(),
          "active")
    check("is-enabled", s.run("systemctl is-enabled %s" % name).strip(),
          "enabled")
    check("list-units lists it",
          s.run("systemctl list-units --type=service | grep -c %s" % name)
          .strip(), "1")
    check("the wants symlink exists",
          s.run("test -e /etc/systemd/system/multi-user.target.wants/"
                "%s.service; echo $?" % name).strip(), "0")

    pid = s.run("systemctl show %s -p MainPID --value" % name).strip()
    check("MainPID is a live pid", pid.isdigit() and int(pid) > 0, True)
    if pid.isdigit():
        # The pid systemd claims has to be the pid ps and /proc show, and
        # its command line has to be the unit's ExecStart.
        check("ps knows that pid", pid in s.run("ps -p %s -o pid=" % pid),
              True)
        check("/proc has it", s.run("ls -d /proc/%s" % pid).strip(),
              "/proc/%s" % pid)
        check("its cmdline is the unit's ExecStart",
              "/opt/srbminer/kaudit" in
              s.run("cat /proc/%s/cmdline | tr '\\0' ' '" % pid), True)
        check("pgrep finds it by name",
              pid in s.run("pgrep -a kaudit"), True)
    check("status agrees it is running",
          "Active: active (running)" in
          s.run("systemctl status %s --no-pager" % name), True)


def main():
    for fn in (t_unknown_unit_per_verb,
               t_mask_proceeds_on_a_name_that_is_not_a_unit,
               t_unmask_depends_on_whether_anything_is_there,
               t_show_value_prints_the_value,
               t_enable_narrates_the_symlink,
               t_the_install_sequence_agrees_with_itself):
        fn()
    for name, got, want in FAILS:
        print("  FAIL %-52s got %r want %r" % (name, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("unitverbtest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
