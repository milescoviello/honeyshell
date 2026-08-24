#!/usr/bin/env python3
"""If you write a unit file, does the box agree the unit exists?

Thirty-sixth coherence sweep, and the sixth taken from a captured
payload. srb.sh finishes its SRBMiner install like this:

    tee /etc/systemd/system/srbminer.service <<EOF ... EOF
    systemctl daemon-reexec
    systemctl daemon-reload
    systemctl enable srbminer.service
    systemctl restart srbminer.service

The file landed -- cat printed it straight back, and the honeypot logged
the whole unit as a persistence event. systemctl then denied the unit
existed at every single step:

    systemctl enable srbminer   Failed to enable ... Unit not found  rc=5
    systemctl restart srbminer  Failed to restart ...                rc=5
    systemctl is-enabled        not-found                            rc=1
    systemctl is-active         inactive                             rc=3
    systemctl status            Unit ... could not be found
    systemctl list-units        absent

_UNITS was a fixed table of the persona's own daemons and nothing ever
looked at the filesystem, so daemon-reload -- whose entire job is to
notice new unit files -- returned 0 and changed nothing. The same blind
spot hid a unit this persona ships itself: /etc/systemd/system/
deploy-worker.service existed on disk and systemctl called it not-found.

Fixed by discovering units from the unit directories, and then by making
the rest agree:

  * A discovered unit defaults to inactive. The baseline daemons default
    to up; a unit that exists only because someone wrote its file has not
    been started yet.
  * enable links to the file that actually exists rather than assuming
    /usr/lib, and is-enabled reads that path.
  * status cites the real path and the real start time. It was claiming
    /lib/systemd/system and "41 days ago" for a unit written a minute
    earlier.
  * ps shows the ExecStart process while the unit is active. status
    reported "Main PID: 26062 (kaudit)" while ps showed nothing -- one
    box, two answers, and the check a miner runs to confirm it is up.
  * is-active exits 3 for a known-but-stopped unit and 4 for one that
    does not exist. Both print "inactive"; the status tells them apart.

Reference measured on the guest, as root, with a temporary unit that was
removed again afterwards:

    is-active (before)          inactive                             rc=3
    daemon-reload                                                    rc=0
    is-enabled (after reload)   disabled                             rc=1
    enable    Created symlink '/etc/systemd/system/multi-user.target.wants/
              probe-tmp.service' -> '/etc/systemd/system/probe-tmp.service'.
    is-enabled (after enable)   enabled                              rc=0
    start                                                            rc=0
    is-active (after start)     active                               rc=0
    status    Loaded: loaded (/etc/systemd/system/probe-tmp.service; enabled;
              preset: enabled) / Active: active (running) since ...; 22ms ago
    list-units                  probe-tmp.service loaded active running ...
    is-active (unknown unit)    inactive                             rc=4

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []

UNIT = """[Unit]
Description=SRBMiner Dual Mining Service
After=network.target

[Service]
ExecStart=/opt/srbminer/kaudit --disable-gpu
Restart=always

[Install]
WantedBy=multi-user.target"""


def sh(write=True):
    s = fs.Shell(fs.VFS(), peer="203.0.113.77")
    s.exec_mode = True
    s.run("mkdir -p /opt/srbminer; echo bin > /opt/srbminer/kaudit; "
          "chmod +x /opt/srbminer/kaudit")
    if write:
        s.run("tee /etc/systemd/system/srbminer.service <<'EOF' >/dev/null\n"
              "%s\nEOF" % UNIT)
    s._err.clear()
    return s


def run(s, cmd):
    out = s.run(cmd)
    err = "".join(s._err)
    s._err.clear()
    return (out + err), s.last_rc


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-48s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


# -- the file makes the unit --------------------------------------------

def t_a_written_unit_is_known():
    s = sh()
    out, rc = run(s, "systemctl is-active srbminer")
    eq("is-active says inactive", out.strip(), "inactive")
    eq("and rc 3 -- known, not running", rc, 3)
    out, rc = run(s, "systemctl is-enabled srbminer")
    eq("is-enabled says disabled", out.strip(), "disabled")
    eq("rc 1", rc, 1)


def t_an_unwritten_unit_is_not_known():
    s = sh(write=False)
    out, rc = run(s, "systemctl is-active srbminer")
    eq("still prints inactive", out.strip(), "inactive")
    eq("but rc 4 -- no such unit", rc, 4)
    out, rc = run(s, "systemctl status srbminer")
    check("status says so", "could not be found" in out, out)
    eq("status rc 4", rc, 4)


def t_the_persona_unit_on_disk_is_known():
    """deploy-worker.service ships with the box and was denied too."""
    s = sh(write=False)
    out, rc = run(s, "systemctl is-active deploy-worker")
    eq("known", rc, 3)
    eq("inactive", out.strip(), "inactive")


# -- the install sequence ------------------------------------------------

def t_the_srbminer_sequence():
    s = sh()
    eq("daemon-reexec", run(s, "systemctl daemon-reexec")[1], 0)
    eq("daemon-reload", run(s, "systemctl daemon-reload")[1], 0)
    out, rc = run(s, "systemctl enable srbminer.service")
    eq("enable succeeds", rc, 0)
    check("and says what it linked",
          "Created symlink" in out and "multi-user.target.wants" in out, out)
    check("the link points at the real file",
          "/etc/systemd/system/srbminer.service" in out, out)
    eq("is-enabled now", run(s, "systemctl is-enabled srbminer")[0].strip(),
       "enabled")
    eq("restart succeeds", run(s, "systemctl restart srbminer.service")[1], 0)
    out, rc = run(s, "systemctl is-active srbminer.service")
    eq("is-active now", out.strip(), "active")
    eq("rc 0", rc, 0)


def t_the_enable_symlink_is_on_disk():
    s = sh()
    run(s, "systemctl enable srbminer")
    link = "/etc/systemd/system/multi-user.target.wants/srbminer.service"
    check("the wants symlink exists", s.fs.exists(link))
    eq("and points at the unit", run(s, "readlink %s" % link)[0].strip(),
       "/etc/systemd/system/srbminer.service")


def t_disable_removes_it_again():
    s = sh()
    run(s, "systemctl enable srbminer")
    out, rc = run(s, "systemctl disable srbminer")
    eq("disable succeeds", rc, 0)
    check("and says what it removed", "Removed" in out, out)
    eq("is-enabled back to disabled",
       run(s, "systemctl is-enabled srbminer")[0].strip(), "disabled")


# -- status agrees with the file and with ps -----------------------------

def t_status_cites_the_real_file():
    s = sh()
    run(s, "systemctl enable srbminer; systemctl start srbminer")
    out, rc = run(s, "systemctl status srbminer")
    eq("rc 0", rc, 0)
    check("the description came from the file",
          "SRBMiner Dual Mining Service" in out, out)
    check("loaded from /etc/systemd/system",
          "/etc/systemd/system/srbminer.service" in out, out)
    check("not from /lib", "/lib/systemd/system/srbminer" not in out, out)
    check("started just now, not at boot",
          "days ago" not in out and "ago" in out, out)


def t_ps_shows_what_status_claims():
    s = sh()
    before = run(s, "ps aux")[0]
    check("nothing before start", "kaudit" not in before, before[-200:])
    run(s, "systemctl start srbminer")
    out = run(s, "ps aux")[0]
    check("the ExecStart process appears", "/opt/srbminer/kaudit" in out,
          out[-300:])
    status = run(s, "systemctl status srbminer")[0]
    pid = [l for l in status.split("\n") if "Main PID" in l]
    check("status names a Main PID", pid, status)
    num = pid[0].split(":")[1].strip().split()[0]
    check("and ps has that pid",
          any(num in l for l in out.split("\n") if "kaudit" in l), out[-300:])
    eq("pgrep agrees", run(s, "pgrep -f kaudit")[0].strip(), num)


def t_stop_removes_it_everywhere():
    s = sh()
    run(s, "systemctl start srbminer")
    run(s, "systemctl stop srbminer")
    eq("is-active", run(s, "systemctl is-active srbminer")[0].strip(),
       "inactive")
    check("ps no longer shows it",
          "kaudit" not in run(s, "ps aux")[0], "still there")


def t_it_appears_in_the_listings():
    s = sh()
    run(s, "systemctl start srbminer")
    check("list-units",
          "srbminer" in run(s, "systemctl list-units --type=service")[0])
    check("list-unit-files",
          "srbminer" in run(s, "systemctl list-unit-files")[0])


# -- the journal has to say the same thing -------------------------------

def t_starting_a_unit_reaches_the_journal():
    """srb.sh signs off with "Use 'sudo journalctl -u srbminer -f'"."""
    s = sh()
    out, _ = run(s, "journalctl -u srbminer -n 3")
    check("nothing before start", "No entries" in out, out)
    run(s, "systemctl start srbminer")
    out, rc = run(s, "journalctl -u srbminer -n 3")
    eq("rc 0", rc, 0)
    check("systemd logged the start",
          "Started srbminer.service - SRBMiner Dual Mining Service." in out,
          out)
    check("tagged systemd[1]", "systemd[1]:" in out, out)


def t_stopping_a_unit_logs_three_lines():
    s = sh()
    run(s, "systemctl start srbminer; systemctl stop srbminer")
    out, _ = run(s, "journalctl -u srbminer -n 6")
    for want in ("Stopping srbminer.service",
                 "srbminer.service: Deactivated successfully.",
                 "Stopped srbminer.service"):
        check("journal has %r" % want[:34], want in out, out)


def t_the_journal_agrees_with_syslog():
    """The journal is derived from syslog, so they cannot disagree."""
    s = sh()
    run(s, "systemctl start srbminer")
    eq("syslog carries the line",
       run(s, "grep -c 'Started srbminer' /var/log/syslog")[0].strip(), "1")
    check("and journalctl shows it",
          "Started srbminer" in run(s, "journalctl -u srbminer")[0])


def t_the_filter_does_not_leak():
    s = sh()
    run(s, "systemctl start srbminer")
    out, _ = run(s, "journalctl -u nosuchunit -n 3")
    check("an unrelated unit gets nothing", "No entries" in out, out)
    out, _ = run(s, "journalctl -u ssh -n 3")
    check("ssh still has its own lines", "No entries" not in out, out)
    check("and they are not srbminer's", "srbminer" not in out, out)


def t_status_ends_with_the_journal():
    s = sh()
    run(s, "systemctl start srbminer")
    out, _ = run(s, "systemctl status srbminer")
    check("the CGroup process line is there",
          "/opt/srbminer/kaudit --disable-gpu" in out, out)
    check("and the journal tail follows it",
          "Started srbminer.service" in out, out)


# -- the baseline must not have moved ------------------------------------

def t_baseline_units_unchanged():
    s = sh(write=False)
    for u, want in (("ssh", "active"), ("cron", "active"),
                    ("nginx", "active")):
        eq("%s still %s" % (u, want),
           run(s, "systemctl is-active %s" % u)[0].strip(), want)
    eq("stopping one still works",
       run(s, "systemctl stop nginx; systemctl is-active nginx")[0].strip(),
       "inactive")


TESTS = [t_starting_a_unit_reaches_the_journal,
         t_stopping_a_unit_logs_three_lines,
         t_the_journal_agrees_with_syslog, t_the_filter_does_not_leak,
         t_status_ends_with_the_journal,
         t_a_written_unit_is_known, t_an_unwritten_unit_is_not_known,
         t_the_persona_unit_on_disk_is_known, t_the_srbminer_sequence,
         t_the_enable_symlink_is_on_disk, t_disable_removes_it_again,
         t_status_cites_the_real_file, t_ps_shows_what_status_claims,
         t_stop_removes_it_everywhere, t_it_appears_in_the_listings,
         t_baseline_units_unchanged]


def main():
    for t in TESTS:
        try:
            t()
        except Exception as exc:                              # noqa: BLE001
            check(t.__name__, False, "crashed: %r" % (exc,))
    print("passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL[:8]))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
