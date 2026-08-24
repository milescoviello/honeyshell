r"""Killing one process is not stopping the service.

Fifty-fourth coherence sweep. Every actor this week hunted processes.
RedTail's clean.sh kills competitors by name; Diicot runs

    ps aux | awk '$3 > 40.0 && $11 !~ /sshd/ {print $2}' \
      | while read pid; do kill -9 $pid; done

and sprays `pkill Opera cnrig java xmrig`; 203.0.113.40 ran
`ps | grep '[Mm]iner'`. So: do the tools that answer "what is running"
agree, and does killing something do what killing that thing does?

Listing was already consistent and is pinned rather than changed. ps and
/proc show the same 28 processes, pidof/pgrep/pgrep -x/ps -C agree on
nginx, sshd and php-fpm, comm matching is exact (`ps -C php-fpm8.4`
matches and `ps -C php-fpm` does not, as on a real box).

The psmisc part of this suite was WRONG and has been corrected: it pinned
the package as absent on the premise that a minimal Debian has no psmisc,
which was never measured. The guest has psmisc 23.7-2 and /usr/bin/killall,
and Diicot's three killall calls on 2026-08-24 got three "command not
found" because of it. See psmisctest.py.

Killing was not consistent.

  1. Any pid of a unit took the whole unit down, so `kill -9 703` -- one
     nginx worker -- was indistinguishable from `systemctl stop nginx`.
     A real master reaps the worker and forks a replacement: the unit
     stays active and the only visible change is the pid. A
     competitor-killer spraying pids from `ps aux | awk '$3 > 40'` would
     have silently shut down the web server.

  2. Only signal 0 was treated as anything other than lethal, because
     the code tested the strings "-0"/"0" rather than the signal. So
     `kill -HUP 701` -- a config reload, the most ordinary thing anyone
     does to nginx -- stopped it, and so did -USR1 (reopen logs) and even
     -CONT, which resumes a process.

  3. Every daemon was parented to pid 1. ps printed "nginx: worker
     process" and "php-fpm: pool www", which state the relationship in
     words, while PPid said all six were children of init. `ps -ejH`,
     `ps --ppid 701` and pstree all read that field, so the process tree
     contradicted the command column beside it.

  4. A worker the master had reforked survived `systemctl stop` and came
     back on start, which is a process outliving a full stop.

Kept as a known simplification: start and restart return a unit to its
canonical pids rather than allocating fresh ones. A real restart gives
every process a new pid.

Run from `honeypot/`, or on the guest.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def shell():
    s = fs.Shell(fs.VFS(), user="root", peer="203.0.113.77")
    s.exec_mode = True
    return s


def run(script, user="root"):
    s = shell()
    out = s.run(script)
    err = "".join(s._err)
    s._err.clear()
    return (out + err), s.last_rc


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-46s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


def pids(s, name="nginx"):
    return sorted(int(x) for x in
                  s.run("pgrep -x %s" % name).split())


def active(s, unit="nginx"):
    return s.run("systemctl is-active %s" % unit).strip()


# -- listing already agreed ----------------------------------------------

def t_ps_and_proc_agree_on_the_count():
    s = shell()
    a = int(s.run("ps -e --no-headers | wc -l").strip())
    b = int(s.run("ls -d /proc/[0-9]* | wc -l").strip())
    eq("ps count == /proc count", a, b)


def t_every_pid_ps_lists_has_a_proc_dir():
    s = shell()
    for p in s.run("ps -e --no-headers -o pid=").split():
        out = s.run("test -d /proc/%s && echo Y" % p).strip()
        eq("/proc/%s exists" % p, out, "Y")


def t_the_process_finders_agree():
    s = shell()
    for name, exact in (("nginx", "nginx"), ("sshd", "sshd"),
                        ("php-fpm8.4", "php-fpm8.4")):
        by_pgrep = sorted(int(x) for x in s.run("pgrep -x %s" % exact).split())
        by_pidof = sorted(int(x) for x in s.run("pidof %s" % exact).split())
        by_ps = sorted(int(x) for x in
                       s.run("ps -C %s -o pid=" % exact).split())
        eq("pgrep vs pidof: %s" % name, by_pgrep, by_pidof)
        eq("pgrep vs ps -C: %s" % name, by_pgrep, by_ps)
        check("%s found at all" % name, len(by_pgrep) > 0, str(by_pgrep))


def t_comm_matching_is_exact():
    """ps -C matches comm, and php-fpm's comm carries its version."""
    s = shell()
    check("ps -C php-fpm8.4 matches",
          s.run("ps -C php-fpm8.4 -o pid=").strip() != "", "")
    eq("ps -C php-fpm matches nothing",
       s.run("ps -C php-fpm -o pid=").strip(), "")
    eq("/proc/660/comm", s.run("cat /proc/660/comm").strip(), "php-fpm8.4")
    eq("/proc/701/comm", s.run("cat /proc/701/comm").strip(), "nginx")


def t_psmisc_is_present_coherently():
    """A real bot called killall three times; the answer must be honest.

    This test used to assert the opposite, on the premise that "a real
    minimal Debian" has no psmisc. The premise was never checked against the
    guest, and the guest has it:

        $ dpkg -l psmisc
        ii  psmisc  23.7-2  amd64  utilities that use the proc file system
        $ which killall
        /usr/bin/killall

    -- and the persona is a *more* populated box than the guest, with nginx,
    mariadb, php-fpm and cron on top of it. Diicot then ran killall three
    times on 2026-08-24 and got three "command not found" from a box whose
    pkill worked. Pinning the absence is what let that stand for a week.
    See psmisctest.py for the rest of the package.
    """
    s = shell()
    for tool in ("killall", "pstree", "fuser", "peekfd"):
        eq("psmisc ships %s" % tool, s.run("command -v %s" % tool).strip(),
           "/usr/bin/%s" % tool)
    out, rc = run("killall nosuchminer")
    check("killall on a name with no process does not say command not found",
          "command not found" not in out, out[:60])
    eq("killall rc when nothing matched", rc, 1)
    out, _ = run("dpkg -l psmisc")
    check("dpkg agrees psmisc is installed",
          bool(re.search(r"^ii\s+psmisc\s", out, re.M)), out[:70])
    for tool in ("ps", "pgrep", "pkill", "top", "free", "vmstat"):
        check("procps has %s" % tool,
              s.run("command -v %s" % tool).strip().endswith(tool), tool)


# -- killing a worker is not stopping the unit ---------------------------

def t_killing_a_worker_respawns_it():
    s = shell()
    before = pids(s)
    eq("three nginx to start", len(before), 3)
    s.run("kill -9 703")
    after = pids(s)
    eq("still three nginx", len(after), 3)
    eq("still active", active(s), "active")
    check("703 is gone", 703 not in after, str(after))
    check("the master survived", 701 in after, str(after))
    check("a new pid took its place", set(after) - set(before) != set(),
          "%s -> %s" % (before, after))


def t_killing_the_master_stops_the_unit():
    s = shell()
    s.run("kill -9 701")
    eq("no nginx left", pids(s), [])
    eq("unit inactive", active(s), "inactive")


def t_both_workers_respawn():
    s = shell()
    s.run("kill -9 702; kill -9 703")
    eq("still three", len(pids(s)), 3)
    eq("still active", active(s), "active")


def t_php_fpm_behaves_the_same_way():
    s = shell()
    s.run("kill -9 662")
    eq("php-fpm still three", len(pids(s, "php-fpm8.4")), 3)
    eq("php-fpm active", active(s, "php8.4-fpm"), "active")
    s.run("kill -9 660")
    eq("master kill stops it", pids(s, "php-fpm8.4"), [])
    eq("php-fpm inactive", active(s, "php8.4-fpm"), "inactive")


def t_a_single_pid_unit_stops():
    s = shell()
    s.run("kill -9 884")
    eq("mariadbd gone", pids(s, "mariadbd"), [])
    eq("mariadb inactive", active(s, "mariadb"), "inactive")


def t_the_respawned_worker_is_real_in_proc():
    """ps and /proc must agree about the replacement, not just ps."""
    s = shell()
    s.run("kill -9 703")
    new = [p for p in pids(s) if p not in (701, 702)]
    eq("exactly one replacement", len(new), 1)
    p = new[0]
    eq("/proc dir exists", s.run("test -d /proc/%d && echo Y" % p).strip(), "Y")
    eq("comm", s.run("cat /proc/%d/comm" % p).strip(), "nginx")
    check("exe points at nginx",
          "/usr/sbin/nginx" in s.run("ls -l /proc/%d/exe" % p), "")
    check("cmdline says worker",
          "worker process" in s.run("cat /proc/%d/cmdline" % p), "")
    eq("parented to the master",
       s.run("grep ^PPid /proc/%d/status" % p).split()[-1], "701")
    eq("old pid really gone",
       s.run("test -d /proc/703 || echo GONE").strip(), "GONE")


# -- signals that are not lethal -----------------------------------------

def t_reload_signals_do_not_stop_a_daemon():
    for sig in ("-HUP", "-USR1", "-USR2", "-1"):
        s = shell()
        s.run("kill %s 701" % sig)
        eq("nginx survives %s" % sig, len(pids(s)), 3)
        eq("active after %s" % sig, active(s), "active")


def t_harmless_signals_do_nothing():
    for sig in ("-0", "-CONT", "-WINCH", "-CHLD"):
        s = shell()
        s.run("kill %s 703" % sig)
        eq("703 survives %s" % sig, pids(s), [701, 702, 703])
        eq("active after %s" % sig, active(s), "active")


def t_terminating_signals_still_terminate():
    for sig in ("-9", "-15", "-TERM", "-KILL", "-QUIT"):
        s = shell()
        s.run("kill %s 701" % sig)
        eq("master dies from %s" % sig, pids(s), [])


def t_a_dropped_binary_has_no_signal_handlers():
    """HUP kills a payload even though it reloads a daemon."""
    s = shell()
    # A valid x86-64 ELF header, or the shell rightly refuses it with
    # "Exec format error" and nothing becomes resident.
    s.run(r"cd /tmp && printf "
          r"'\177ELF\002\001\001\000\000\000\000\000\000\000"
          r"\000\000\002\000>\000\001\000\000\000' > miner && "
          r"printf 'padpadpadpadpadpadpadpadpadpadpad' >> miner && "
          r"chmod +x miner && ./miner")
    running = s.run("pgrep -f miner").split()
    if not running:
        check("dropped process registered", False, "nothing started")
        return
    p = running[0]
    s.run("kill -HUP %s" % p)
    eq("HUP killed the payload", s.run("pgrep -f miner").strip(), "")


# -- the process tree ----------------------------------------------------

def t_workers_are_children_of_their_master():
    s = shell()
    for worker, master in ((702, 701), (703, 701), (661, 660), (662, 660)):
        eq("PPid of %d" % worker,
           s.run("grep ^PPid /proc/%d/status" % worker).split()[-1],
           str(master))
    for top in (701, 660, 884, 498):
        eq("PPid of %d" % top,
           s.run("grep ^PPid /proc/%d/status" % top).split()[-1], "1")


def t_ps_ppid_finds_the_children():
    s = shell()
    eq("ps --ppid 701", sorted(int(x) for x in
                               s.run("ps --ppid 701 -o pid=").split()),
       [702, 703])
    eq("ps --ppid 660", sorted(int(x) for x in
                               s.run("ps --ppid 660 -o pid=").split()),
       [661, 662])


# -- restart bookkeeping -------------------------------------------------

def t_a_respawned_worker_does_not_survive_a_stop():
    s = shell()
    s.run("kill -9 703")
    s.run("systemctl stop nginx")
    eq("nothing left after stop", pids(s), [])
    s.run("systemctl start nginx")
    eq("canonical pids are back", pids(s), [701, 702, 703])
    eq("active again", active(s), "active")


def t_restart_clears_the_respawn():
    s = shell()
    s.run("kill -9 703")
    s.run("systemctl restart nginx")
    eq("restart returns canonical pids", pids(s), [701, 702, 703])
    s.run("kill -9 703")
    eq("and killing again still respawns", len(pids(s)), 3)


def t_reload_keeps_the_current_pids():
    """systemctl reload is not a restart; it must not renumber anything."""
    s = shell()
    s.run("kill -9 703")
    before = pids(s)
    s.run("systemctl reload nginx")
    eq("reload changed nothing", pids(s), before)


TESTS = [t_ps_and_proc_agree_on_the_count,
         t_every_pid_ps_lists_has_a_proc_dir, t_the_process_finders_agree,
         t_comm_matching_is_exact, t_psmisc_is_present_coherently,
         t_killing_a_worker_respawns_it, t_killing_the_master_stops_the_unit,
         t_both_workers_respawn, t_php_fpm_behaves_the_same_way,
         t_a_single_pid_unit_stops, t_the_respawned_worker_is_real_in_proc,
         t_reload_signals_do_not_stop_a_daemon, t_harmless_signals_do_nothing,
         t_terminating_signals_still_terminate,
         t_a_dropped_binary_has_no_signal_handlers,
         t_workers_are_children_of_their_master, t_ps_ppid_finds_the_children,
         t_a_respawned_worker_does_not_survive_a_stop,
         t_restart_clears_the_respawn, t_reload_keeps_the_current_pids]


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
