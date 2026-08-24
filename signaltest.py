#!/usr/bin/env python3
"""Do the two ways to kill a process agree that it died?

Attackers kill things: rival miners, the service holding a port, their own
loader once it has forked. So "is that process dead" gets asked by kill,
pkill, ps and systemctl, and they did not agree.

  - `pkill -9 -x mariadbd` matched the process, logged that it had, and
    returned 0 without signalling anything: ps and systemctl both still
    showed mariadbd running afterwards. `kill` on the same pid did take it
    down. Two ways to kill a process, two different outcomes. pkill goes
    through kill's own code path now, so they cannot diverge again.
  - `timeout 1 sleep 5` returned 0 and took five seconds. 124 is the whole
    point of the command -- it is how every wrapper distinguishes a command
    that finished from one that was killed -- and the elapsed time gave it
    away before the exit status did. -s and -k were not parsed at all, so
    `timeout -s KILL 1 sleep 5` ran a command called "-s".
  - `nohup` printed "appending output to 'nohup.out'" and created no such
    file, discarding the command's output with it: `nohup echo x` printed
    only the notice. The notice belongs on stderr, the output belongs in
    the file, and the file is 0600.
  - `kill -NOSUCHSIG 1` returned 0 and did nothing -- silent success for a
    signal that does not exist.
  - `kill` abandoned the rest of its target list on the first bad pid,
    where a real one reports that pid and carries on.

Run from `honeypot/`, or on the guest.
"""

import os
import re
import sys
import time

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
        print("  FAIL %-52s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


def alive(s, comm):
    o, _ = run(s, "ps -eo comm | grep -cx %s" % comm)
    return int(o.strip() or 0)


def t_pkill_and_kill_agree_that_a_process_died():
    """The contradiction this sweep started from."""
    for method in ("kill", "pkill"):
        s = sh()
        before = alive(s, "mariadbd")
        check("%s: mariadbd is running first" % method, before >= 1,
              "count %d" % before)
        svc, _ = run(s, "systemctl is-active mariadb")
        eq("%s: and its unit is active" % method, svc.strip(), "active")
        if method == "kill":
            pid, _ = run(s, "pgrep -x mariadbd | head -1")
            o, rc = run(s, "kill -9 %s" % pid.strip())
        else:
            o, rc = run(s, "pkill -9 -x mariadbd")
        eq("%s rc" % method, rc, 0)
        eq("%s: ps no longer lists it" % method, alive(s, "mariadbd"), 0)
        o, _ = run(s, "pgrep -x mariadbd")
        eq("%s: pgrep no longer finds it" % method, o.strip(), "")
        svc, _ = run(s, "systemctl is-active mariadb")
        eq("%s: and the unit went inactive" % method, svc.strip(), "inactive")


def t_pkill_matching_rules():
    s = sh()
    o, rc = run(s, "pkill -x definitelynotaprocess")
    eq("no match is rc 1", rc, 1)
    o, rc = run(s, "pkill")
    eq("no pattern is rc 2", rc, 2)
    check("with pkill's wording", "no matching criteria" in o, o[:70])
    # -x is exact: a longer name must not match.
    s = sh()
    o, rc = run(s, "pkill -x ngin")
    eq("-x does not match a prefix", rc, 1)
    eq("and nginx is untouched", alive(s, "nginx") > 0, True)
    # without -x it is a substring regex
    s = sh()
    o, rc = run(s, "pkill ngin")
    eq("without -x a substring matches", rc, 0)
    eq("and nginx is gone", alive(s, "nginx"), 0)


def t_killing_a_master_takes_its_workers_without_complaining():
    s = sh()
    n = alive(s, "nginx")
    check("nginx has more than one process", n > 1, "count %d" % n)
    o, rc = run(s, "pkill nginx")
    eq("pkill rc", rc, 0)
    eq("pkill says nothing about workers that went with the master",
       o.strip(), "")
    eq("all of them are gone", alive(s, "nginx"), 0)


def t_kill_reports_a_bad_target_and_keeps_going():
    s = sh()
    o, rc = run(s, "kill -0 1 99999 2")
    eq("rc is 1 when one target is missing", rc, 1)
    check("the missing pid is named", "99999" in o, o[:80])
    check("and only that one", o.count("No such process") == 1, o[:120])


def t_an_unknown_signal_is_refused():
    s = sh()
    for form in ("kill -NOSUCHSIG 1", "kill -s NOPE 1", "kill -SIGBOGUS 1"):
        o, rc = run(s, form)
        eq("%s rc" % form, rc, 1)
        check("%s message" % form, "invalid signal specification" in o,
              o[:80])
    for form in ("kill -9 1", "kill -KILL 1", "kill -SIGKILL 1",
                 "kill -s KILL 1", "kill -s 9 1", "kill -0 1"):
        o, rc = run(s, form)
        eq("%s is accepted" % form, rc, 0)


def t_kill_l_and_trap_l_are_the_same_list():
    s = sh()
    a, rca = run(s, "kill -l")
    b, rcb = run(s, "trap -l")
    eq("kill -l rc", rca, 0)
    eq("trap -l rc", rcb, 0)
    eq("kill -l and trap -l print the same list", a, b)
    check("the list starts at SIGHUP", a.startswith(" 1) SIGHUP\t"), repr(a[:30]))
    # bash 5.2 lists 62 named signals -- 1..31 and 34..64, skipping the two
    # glibc takes -- five to a line, tab separated. Checked against a real
    # bash, not against this implementation.
    eq("kill -l has 13 lines like bash", len(a.rstrip("\n").split("\n")), 13)
    eq("kill -l names 62 signals", len(re.findall(r"\d+\) SIG", a)), 62)
    check("columns are tab separated", "\t" in a.splitlines()[0],
          repr(a.splitlines()[0]))
    check("no line is space padded",
          not any(l.rstrip("\t") != l.rstrip() for l in a.splitlines()[:12]),
          repr(a.splitlines()[0]))
    o, _ = run(s, "kill -l 64")
    eq("kill -l 64 is RTMAX", o.strip(), "RTMAX")
    o, _ = run(s, "kill -l RTMIN")
    eq("kill -l RTMIN is 34", o.strip(), "34")
    o, rc = run(s, "kill -l 32")
    eq("32 has no name, as in bash", rc, 1)
    # Name and number must round trip.
    for num, name in ((1, "HUP"), (9, "KILL"), (15, "TERM"), (2, "INT")):
        o, _ = run(s, "kill -l %d" % num)
        eq("kill -l %d" % num, o.strip(), name)
        o, _ = run(s, "kill -l %s" % name)
        eq("kill -l %s" % name, o.strip(), str(num))
    o, rc = run(s, "kill -l 999")
    eq("an out-of-range number is an error", rc, 1)


def t_timeout_reports_that_it_timed_out():
    s = sh()
    t0 = time.time()
    o, rc = run(s, "timeout 1 sleep 5")
    el = time.time() - t0
    eq("timeout rc is 124", rc, 124)
    check("and it returned at the deadline, not when the command would have",
          el < 3.0, "%.1fs elapsed" % el)
    t0 = time.time()
    o, rc = run(s, "timeout 5 echo hi")
    eq("a command that finishes keeps its own status", (o, rc), ("hi\n", 0))
    check("and returns immediately", time.time() - t0 < 2.0, "slow")
    o, rc = run(s, "timeout -s KILL 1 sleep 5")
    eq("-s is parsed, not run as the command", rc, 124)
    check("and no command called -s was attempted",
          "-s: command not found" not in o, o[:80])
    o, rc = run(s, "timeout -k 1 1 sleep 5")
    eq("-k takes its argument too", rc, 124)
    o, rc = run(s, "timeout 1m echo ok")
    eq("a unit suffix is understood", (o.strip(), rc), ("ok", 0))
    o, rc = run(s, "timeout")
    eq("no operand is rc 125", rc, 125)
    o, rc = run(s, "timeout -s NOPE 1 echo x")
    eq("a bad signal is rc 125", rc, 125)
    check("with timeout's wording", "invalid signal" in o, o[:70])
    o, rc = run(s, "timeout 5 nosuchcommand")
    eq("a missing command is rc 127", rc, 127)


def t_nohup_writes_the_file_it_announces():
    s = sh()
    run(s, "rm -f /root/nohup.out")
    o, rc = run(s, "cd /root && nohup echo hello")
    eq("nohup rc", rc, 0)
    check("the notice names nohup.out", "appending output to 'nohup.out'" in o,
          o[:90])
    eq("the command's output is not on stdout", "hello" in o.split("\n")[0],
       False)
    body, rc = run(s, "cat /root/nohup.out")
    eq("the output is in the file", body, "hello\n")
    ls, _ = run(s, "ls -l /root/nohup.out")
    check("and the file is 0600, as GNU nohup creates it",
          ls.startswith("-rw-------"), ls[:40])
    run(s, "cd /root && nohup echo second")
    body, _ = run(s, "cat /root/nohup.out")
    eq("a second run appends", body, "hello\nsecond\n")
    o, rc = run(s, "nohup")
    eq("no operand is rc 125", rc, 125)
    check("with nohup's wording", "missing operand" in o, o[:70])


def t_ps_and_proc_agree_after_a_kill():
    s = sh()
    pid, _ = run(s, "pgrep -x cron | head -1")
    pid = pid.strip()
    check("cron has a pid", pid.isdigit(), pid)
    if not pid.isdigit():
        return
    o, rc = run(s, "test -d /proc/%s && echo yes" % pid)
    eq("/proc has it before", (o.strip(), rc), ("yes", 0))
    run(s, "kill -9 %s" % pid)
    o, rc = run(s, "test -d /proc/%s && echo yes" % pid)
    eq("/proc drops it after", rc, 1)
    o, _ = run(s, "ps -eo pid | grep -cx ' *%s'" % pid)
    o2, _ = run(s, "ps -p %s -o comm=" % pid)
    eq("ps drops it too", o2.strip(), "")
    o, rc = run(s, "kill -0 %s" % pid)
    eq("and kill -0 now fails for it", rc, 1)


def t_pid_one_and_kernel_threads_survive():
    s = sh()
    o, rc = run(s, "kill -9 1")
    eq("signalling pid 1 succeeds", rc, 0)
    o, _ = run(s, "ps -p 1 -o comm=")
    eq("but init is still there", o.strip(), "systemd")
    o, _ = run(s, "ps -eo pid,comm | grep ' \\[' | head -1 | awk '{print $1}'")
    kt = o.strip()
    if kt.isdigit():
        run(s, "kill -9 %s" % kt)
        o, _ = run(s, "ps -p %s -o comm=" % kt)
        check("a kernel thread survives SIGKILL", o.strip() != "", "gone")


def t_the_tools_that_are_present_are_present_consistently():
    """This asserted the opposite, and so did killtest.py.

    Both pinned psmisc as absent on the premise that this is a minimal
    Debian. Neither checked the guest, which has psmisc 23.7-2 and
    /usr/bin/killall -- and the persona is a more populated box than the
    guest, with nginx, mariadb, php-fpm and cron on top of it. Diicot ran
    killall three times on 2026-08-24 and got three "command not found"
    from a box whose pkill worked. Two suites agreeing with each other is
    not evidence when both took the same unmeasured premise.

    What is worth pinning is the coherence, in either direction: the tool
    resolves, dpkg says which package owns it, and that package is
    installed at a version. See psmisctest.py for the behaviour.
    """
    s = sh()
    for tool in ("killall", "fuser", "pstree"):
        path, rc = run(s, "command -v %s" % tool)
        eq("%s resolves" % tool, rc, 0)
        eq("%s is where dpkg says" % tool, path.strip(), "/usr/bin/%s" % tool)
        owner, rc2 = run(s, "dpkg -S /usr/bin/%s" % tool)
        eq("dpkg names its owner" % (), owner.strip(),
           "psmisc: /usr/bin/%s" % tool)
        ver, rc3 = run(s, "dpkg-query -W -f '${Version}' psmisc")
        eq("and psmisc is installed", rc3, 0)
        eq("at the guest's version", ver.strip(), "23.7-2")
    for tool in ("kill", "pkill", "pgrep", "timeout", "nohup"):
        path, rc = run(s, "command -v %s" % tool)
        eq("%s is available" % tool, rc, 0)


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
