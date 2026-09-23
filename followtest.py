#!/usr/bin/env python3
"""Does `-f` actually follow?

203.0.113.73 installed srbminer.service on 2026-08-30, then ran

    journalctl -u srbminer -f          x4
    journalctl -u srbminer -f -n 100
    journalctl -u srbminer -f          x2
    journalctl -u xmrig -f

-f was parsed as an unknown flag and dropped, so every one of those printed
the entire 288 KB journal and handed the prompt straight back. The retry
pattern is what an operator does when the log they just installed will not
stay on screen; six tries is someone deciding the box is not real.

Two separate defects were behind one flag:

  * it did not follow -- the command returned instantly where the real one
    blocks until Ctrl-C, and
  * it did not bound the backlog -- real journalctl -f prints the last ten
    lines, ours printed all 3016.

`tail -f` and `tail -F` had the identical defect and are checked here too:
they are the other half of what anyone runs to watch a box they have taken.

The follow itself is split across two files, so this suite checks the shell
half (backlog, request, poller) and live-verifies nothing: the channel half
is exercised over real SSH by hand, because a follow that only works
in-process is the bug that shipped last time.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

ok = bad = 0


def check(name, got, want):
    global ok, bad
    if got == want:
        ok += 1
    else:
        bad += 1
        print("  FAIL %s" % name)
        print("       want %r" % (want,))
        print("       got  %r" % (got,))


def sh():
    s = fs.Shell(vfs=fs.VFS(), peer="198.51.100.77", peer_port=51000)
    s.run("true")
    return s


def lines(text):
    return [l for l in text.split("\n") if l and not l.startswith("-- ")]


def out(res):
    return (res[0] if isinstance(res, tuple) else res) or ""


def main():
    s = sh()

    # -f bounds the backlog to ten lines, like the real one.
    for cmd in ("journalctl -f", "journalctl -u ssh -f",
                "journalctl --follow", "journalctl -f -u cron"):
        check("%s is ten lines" % cmd, len(lines(out(s.run(cmd)))), 10)

    # ...and an explicit -n still wins over the implied ten.
    check("-f -n 3 honours -n", len(lines(out(s.run("journalctl -f -n 3")))), 3)
    check("-n 3 -f honours -n", len(lines(out(s.run("journalctl -n 3 -f")))), 3)

    # Without -f the whole journal is still there: -f bounds the view, it
    # does not shrink the journal.
    full = len(lines(out(s.run("journalctl"))))
    check("plain journalctl is unbounded", full > 100, True)

    # Every follow spelling registers a request, and nothing else does.
    for cmd, kind in (("journalctl -f", "journal"),
                      ("journalctl --follow", "journal"),
                      ("journalctl -u ssh -f", "journal"),
                      ("tail -f /var/log/syslog", "file"),
                      ("tail -F /var/log/syslog", "file"),
                      ("tail --follow /var/log/syslog", "file"),
                      ("tail -n 5 -f /var/log/auth.log", "file")):
        s.run(cmd)
        req = getattr(s, "_follow_req", None)
        check("%s registers %s" % (cmd, kind), req[0] if req else None, kind)

    for cmd in ("journalctl", "journalctl -n 20", "tail /var/log/syslog",
                "tail -n 3 /var/log/syslog", "ls /tmp", "echo -f"):
        s.run(cmd)
        check("%s registers nothing" % cmd,
              getattr(s, "_follow_req", None), None)

    # A request never outlives the command that made it.
    s.run("journalctl -f")
    check("request survives its own command",
          getattr(s, "_follow_req", None) is not None, True)
    s.run("echo next")
    check("request cleared by the next command",
          getattr(s, "_follow_req", None), None)

    # The poller does not replay what the backlog already printed: an
    # immediate poll is empty, and the marker does not move.
    s.run("journalctl -u ssh -f")
    req = s._follow_req
    m0 = s.follow_open(req)
    txt, m1 = s.follow_poll(req, m0)
    check("immediate poll is empty", txt, "")
    check("marker steady", m1, m0)
    txt2, m2 = s.follow_poll(req, m1)
    check("second poll is empty too", txt2, "")
    check("marker still steady", m2, m1)

    # A file follow is byte-offset based and behaves the same way.
    s.run("tail -f /var/log/syslog")
    freq = s._follow_req
    fm0 = s.follow_open(freq)
    ftxt, fm1 = s.follow_poll(freq, fm0)
    check("file poll is empty", ftxt, "")
    check("file marker steady", fm1, fm0)
    check("file marker is the file size", fm0 > 0, True)

    # ...and a file that grows is streamed from the mark, not from the top.
    s.run("touch /tmp/f.log && echo one >> /tmp/f.log")
    s.run("tail -f /tmp/f.log")
    greq = s._follow_req
    gm = s.follow_open(greq)
    s.run("echo two >> /tmp/f.log")
    gtxt, gm2 = s.follow_poll(greq, gm)
    check("grown file streams only the new line", gtxt, "two\n")
    check("grown file marker advanced", gm2 > gm, True)
    gtxt2, _ = s.follow_poll(greq, gm2)
    check("and does not repeat it", gtxt2, "")

    # A truncation re-baselines instead of replaying the whole file.
    s.run("> /tmp/f.log")
    ttxt, tm = s.follow_poll(greq, gm2)
    check("truncation streams nothing", ttxt, "")
    check("truncation rewinds the mark", tm, 0)

    # A follow on a unit that does not exist is not an error and not a
    # crash -- it is an empty follow, which is what the real one does.
    s.run("journalctl -u nosuchunit -f")
    nreq = getattr(s, "_follow_req", None)
    check("unknown unit still registers", nreq[0] if nreq else None, "journal")
    nm = s.follow_open(nreq)
    check("unknown unit backlog is empty", nm, 0)
    ntxt, _ = s.follow_poll(nreq, nm)
    check("unknown unit poll is empty", ntxt, "")

    # The unit an attacker installs is followable by name, which is the
    # whole point.
    s.run("mkdir -p /etc/systemd/system")
    s.run("printf '[Unit]\\nDescription=X\\n[Service]\\n"
          "ExecStart=/opt/k/kaudit\\n' > /etc/systemd/system/zz.service")
    s.run("systemctl daemon-reload; systemctl restart zz")
    s.run("journalctl -u zz -f")
    zreq = getattr(s, "_follow_req", None)
    check("attacker unit registers a follow",
          zreq[0] if zreq else None, "journal")
    check("attacker unit has a backlog", s.follow_open(zreq) > 0, True)

    print()
    print("=" * 58)
    print("followtest: passed %d, failed %d" % (ok, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
