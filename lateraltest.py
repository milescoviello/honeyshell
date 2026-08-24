#!/usr/bin/env python3
"""Where did they try to go next?

An actor who lands on a box looks for the next one, and ssh and ping are
how they do it. Both parsed their options by taking the first token that
did not start with a dash as the destination -- which is the *argument* of
whatever flag came before it:

    ssh -o StrictHostKeyChecking=no root@10.0.0.5 id
        -> "ssh: connect to host StrictHostKeyChecking=no port 22"

and that flag is in essentially every automated pivot, because unattended
ssh cannot answer a host-key prompt. -p, -i and -l failed identically, and
-p was ignored twice over: the port stayed 22 in the message. ping had the
same bug -- `ping -c 2 host` tried to resolve "2" -- plus the attached
form was not parsed at all, so `ping -c1 host` sent the default four when
the whole reason to write -c1 is to send one.

Worse than the wrong message: ssh_outbound recorded no host. The single
thing worth knowing about a lateral attempt -- where they were going --
was not captured, on the event named for capturing it.

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                        # noqa: E402

PASS, FAIL = [], []


def sh():
    events = []
    s = fs.Shell(fs.VFS(), log=lambda **k: events.append(k),
                 peer="203.0.113.77")
    s.exec_mode = True
    s.events = events
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


def outbound(s):
    return [e for e in s.events if e.get("event") == "ssh_outbound"]


def t_the_flag_every_pivot_uses():
    """Unattended ssh cannot answer a host-key prompt, so this option is on
    almost every one."""
    s = sh()
    out, rc = run(s, "ssh -o StrictHostKeyChecking=no root@10.0.0.5 id")
    eq("rc", rc, 255)
    eq("the host is the host", out.strip(),
       "ssh: connect to host 10.0.0.5 port 22: Connection timed out")
    ev = outbound(s)
    eq("one event", len(ev), 1)
    eq("target recorded", ev[0].get("target"), "10.0.0.5")
    eq("user recorded", ev[0].get("user"), "root")
    eq("remote command recorded", ev[0].get("remote_command"), "id")


def t_every_value_taking_flag():
    s = sh()
    for cmd, host in (
            ("ssh -i /root/.ssh/id_rsa root@10.0.0.5 id", "10.0.0.5"),
            ("ssh -l root 10.0.0.5 id", "10.0.0.5"),
            ("ssh -F /dev/null root@10.0.0.5 id", "10.0.0.5"),
            ("ssh -o A=b -o C=d root@10.0.0.5 id", "10.0.0.5"),
            ("ssh -J jump@1.2.3.4 root@10.0.0.5 id", "10.0.0.5"),
            ("ssh -qT root@10.0.0.5 id", "10.0.0.5")):
        out, _rc = run(s, cmd)
        check("%s -> %s" % (cmd[:44], host),
              "connect to host %s port" % host in out, out[:70])


def t_the_port_is_the_port():
    """-p was consumed as the destination and ignored as a port, so the
    message said 22 whatever was asked for."""
    s = sh()
    for cmd in ("ssh -p 2222 root@10.0.0.5 id", "ssh -p2222 root@10.0.0.5 id"):
        out, _rc = run(s, cmd)
        check("%s uses 2222" % cmd[:30],
              "10.0.0.5 port 2222" in out, out[:70])
    eq("and the event carries it", outbound(s)[-1].get("port"), 2222)


def t_the_user_comes_from_either_spelling():
    s = sh()
    run(s, "ssh admin@10.0.0.9 whoami")
    eq("user@host", outbound(s)[-1].get("user"), "admin")
    run(s, "ssh -l admin 10.0.0.9 whoami")
    eq("-l user", outbound(s)[-1].get("user"), "admin")
    run(s, "ssh 10.0.0.9 whoami")
    eq("no user given", outbound(s)[-1].get("user"), None)


def t_the_remote_command_is_kept_whole():
    s = sh()
    run(s, "ssh -o A=b root@10.0.0.9 uname -a")
    eq("multi-word command", outbound(s)[-1].get("remote_command"),
       "uname -a")
    run(s, "ssh root@10.0.0.9")
    eq("no command", outbound(s)[-1].get("remote_command"), "")


def t_ssh_with_no_destination():
    s = sh()
    out, rc = run(s, "ssh")
    eq("rc", rc, 255)
    check("usage", out.startswith("usage: ssh"), out[:40])
    eq("and nothing is logged as an attempt", outbound(s), [])


def t_ping_count_both_spellings():
    """`ping -c 2 host` resolved "2"; `ping -c1 host` sent four."""
    s = sh()
    for cmd, n in (("ping -c1 10.0.0.5", 1), ("ping -c 2 10.0.0.5", 2),
                   ("ping -c 3 -W 1 10.0.0.5", 3),
                   ("ping -c1 -W1 10.0.0.5", 1),
                   ("ping -c 1 -i 0.2 -w 2 10.0.0.5", 1),
                   ("ping 10.0.0.5", 4)):
        out, _rc = run(s, cmd)
        check("%s sends %d" % (cmd, n),
              "%d packets transmitted" % n in out, out[-70:])
        check("%s names the host" % cmd, "10.0.0.5 ping statistics" in out,
              out[:60])


def t_ping_still_resolves_and_refuses():
    s = sh()
    out, _rc = run(s, "ping -c1 web01")
    check("a known name resolves", out.startswith("PING web01 ("), out[:40])
    out, rc = run(s, "ping -c1 nosuchhostname")
    eq("an unknown short name fails in the resolver", rc, 2)
    check("with ping's wording", "Name or service not known" in out,
          out[:60])
    out, rc = run(s, "ping")
    eq("no destination", rc, 2)
    check("usage error", "Destination address required" in out, out[:50])


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("t_")]


def main():
    for t in TESTS:
        try:
            t()
        except Exception as exc:                              # noqa: BLE001
            check(t.__name__, False, "crashed: %r" % (exc,))
    print("passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL[:6]))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
