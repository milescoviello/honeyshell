#!/usr/bin/env python3
"""Does every path this box names actually exist?

Sweep 228 found one of these the hard way: the nightly batch job's
`--out /data/out` pointed at a directory that was not there, and it was
only visible at night because the job starts at 02:00 and no gate had ever
run then. This suite is that check generalised -- take every filesystem
path the box names *anywhere* it speaks about itself, and open it.

Sources: `ps aux`, `crontab -l`, /etc/crontab, /etc/cron.d/*, the systemd
unit files, and /etc/fstab. Run against the live persona it found five more
on top of /data/out:

    /data/runs/sft-70b                            ps aux (training job)
    /etc/dcgm-exporter/dcp-metrics-included.csv   ps aux (dcgm-exporter -f)
    /etc/php/8.4/fpm/php-fpm.conf                 ps aux (php-fpm master)
    /usr/lib/.../e2fsprogs/e2scrub_all_cron       /etc/cron.d

and one that looked like a sixth and was not: /var/www/artisan, named by
deploy-worker.service. That unit is `disabled; inactive (dead)`, no php
process is running, and /var/www/html is WordPress -- webtest pins the
absence on purpose. Creating the app to satisfy a path scan would have
made the box less real, so the rule below carries the exception instead.

Each one is a file that a *running process* or an *installed package*
points at, so `ls` on a path copied straight out of `ps aux` -- which is
the first thing anyone does after `ps aux` -- answered "No such file or
directory".

## The exception, which is the interesting part

/usr/sbin/anacron is named by /etc/crontab and does *not* exist, and that
is correct. Debian ships /etc/crontab with

    25 6 * * * root test -x /usr/sbin/anacron || { cd / && run-parts ... }

whether or not anacron is installed, and `dpkg -l anacron` on this box says
it is not. A real Debian box without the package looks exactly like this.
So the rule this suite enforces is not "every named path exists" -- it is
"every named path exists unless the box also says it should not", and the
package list is what says so.

That distinction is why the fix list was five and not six. Adding
/usr/sbin/anacron would have made the box *less* like a real one.

## And the trap in fixing it

The first attempt wrote php-fpm.conf and e2scrub_all_cron and neither
appeared: VFS.write() does not create intermediate directories, and
/etc/php and .../e2fsprogs did not exist, so the writes silently did
nothing. A fix that reports success and changes nothing is worse than no
fix, so this suite reads the files, not just their names.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fakeshell

CHECKS, FAILS = [], []
PATH_RE = re.compile(
    r"(/(?:etc|var|usr|opt|data|home|srv|root|run|mnt)/[A-Za-z0-9_./+-]{2,60})")

#: Named, absent, and right to be absent: /etc/crontab carries these lines
#: on every Debian box, and the guard is what makes the absence correct.
GUARDED = {"/usr/sbin/anacron": "anacron"}


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want,
                        ("\n  -- " + str(note)) if note else ""))


def shell():
    return fakeshell.Shell(vfs=fakeshell.VFS(), peer="198.51.100.13",
                           peer_port=40333)


def main():
    sh = shell()
    def run(c):
        return sh.run(c) or ""

    sources = {
        "ps aux": run("ps aux"),
        "crontab -l": run("crontab -l"),
        "/etc/crontab": run("cat /etc/crontab 2>/dev/null"),
        "/etc/cron.d": run("cat /etc/cron.d/* 2>/dev/null"),
        "systemd units": run("cat /etc/systemd/system/*.service 2>/dev/null"),
        "/etc/fstab": run("cat /etc/fstab"),
    }
    # crontab -l is allowed to be empty: there is no root crontab on this
    # box, and Debian's crontab(1) then prints "no crontab for root" on
    # stderr and exits 1, so an empty stdout is the correct answer rather
    # than a source that failed to read.
    filebacked = {k: v for k, v in sources.items() if k != "crontab -l"}
    check("the file-backed sources all read",
          sorted(k for k, v in filebacked.items() if not v.strip()), [],
          str({k: len(v) for k, v in sources.items()}))
    empty_out = run("crontab -l 2>/dev/null")
    err = run("crontab -l 2>&1 >/dev/null")
    check("crontab -l prints nothing on stdout with no crontab",
          empty_out.strip(), "")
    check("...and says so on stderr, as crontab(1) does",
          "no crontab for" in err, True, err[:60])

    named = {}
    for label, text in sources.items():
        for m in PATH_RE.findall(text):
            p = m.rstrip(".,;:)\"'").rstrip("/")
            if len(p.split("/")) >= 3 and not any(c in p for c in "*?[]"):
                named.setdefault(p, set()).add(label)
    check("it names a useful number of paths", len(named) >= 20, True, len(named))

    missing = []
    for p in sorted(named):
        if run("test -e '%s' && echo Y || echo N" % p).strip() != "Y":
            missing.append(p)

    # Absent on purpose: the package is not installed and the caller guards.
    for p, pkg in GUARDED.items():
        if p in missing:
            installed = run("dpkg -l %s 2>/dev/null | grep -c '^ii'" % pkg).strip()
            check("%s is absent because %s is not installed" % (p, pkg),
                  installed, "0",
                  "if the package were installed the file would have to exist")
            guarded = any(("test -x %s" % p) in t or ("test -e %s" % p) in t
                          for t in sources.values())
            check("...and its caller guards on it", guarded, True)
            missing.remove(p)

    # Named only by a unit that is not running. deploy-worker.service
    # points at /var/www/artisan, and that unit is `disabled; inactive
    # (dead)` while /var/www/html is WordPress -- the story is a Laravel
    # deploy that was removed and left its unit behind, which is a thing
    # that happens to real machines. A stopped unit naming a path that is
    # gone is what that looks like, so it is allowed to be missing *while
    # the unit stays stopped*. Enable or start it and this fires.
    still = []
    for p in missing:
        owners = named.get(p, set())
        if owners == {"systemd units"}:
            unit = ""
            for f in run("ls /etc/systemd/system/*.service 2>/dev/null").split():
                if p in run("cat %s 2>/dev/null" % f):
                    unit = os.path.basename(f)
                    break
            if unit:
                st = run("systemctl is-active %s" % unit).strip()
                en = run("systemctl is-enabled %s" % unit).strip()
                check("%s is named only by %s, which is not running"
                      % (p, unit), (st, en), ("inactive", "disabled"),
                      "a path may only be missing while the unit naming it "
                      "is stopped")
                continue
        still.append(p)

    check("every other path the box names exists", still, [],
          "a path out of `ps aux` that `ls` cannot open")

    # -- the files, not just their names -------------------------------
    for path, needle, what in (
            ("/etc/php/8.4/fpm/php-fpm.conf", "[global]", "php-fpm's config"),
            ("/etc/php/8.4/fpm/pool.d/www.conf", "listen =", "its www pool"),
            ("/etc/dcgm-exporter/dcp-metrics-included.csv", "DCGM_FI_DEV_",
             "the metric list dcgm-exporter is started with"),
            ("/usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron", "#!/bin/",
             "the cron.d target"),
            ("/data/runs/sft-70b/config.yaml", "output_dir",
             "the training run's own directory"),
    ):
        body = run("cat '%s' 2>/dev/null" % path)
        check("%s reads back (%s)" % (path.split("/")[-1], what),
              needle in body, True, body[:60])

    check("e2scrub_all_cron is executable",
          run("test -x /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron "
              "&& echo Y || echo N").strip(), "Y")
    check("the removed Laravel app really is gone",
          run("test -e /var/www/artisan && echo Y || echo N").strip(), "N",
          "webtest.t_no_laravel_remnants pins this; the unit that names it "
          "is disabled and dead")
    check("the training run dir belongs to the user running the job",
          run("stat -c %U /data/runs/sft-70b").strip(), "mlops")

    print("%d/%d assertions pass" % (sum(CHECKS), len(CHECKS)))
    for f in FAILS:
        print(f)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
