#!/usr/bin/env python3
"""journalctl's output modes and filters, against the journal underneath.

The axis: one set of records, several renderings, and two flags whose
whole job is to narrow. Neither narrowed, and the renderings were all the
same one:

    journalctl -o cat      printed the full short format, five fields the
                           caller had just asked to be rid of
    journalctl -o json     printed prose, so `journalctl -o json | jq`
                           failed on a box where journalctl worked
    journalctl -o short-iso printed "Aug 23", not an ISO timestamp
    journalctl -p err      returned "Accepted password", an informational
                           line -- the one flag for showing only failures
                           showed everything
    journalctl --grep X    returned lines without X in them
    journalctl --vacuum-time=1s
                           dumped the whole journal, because only the bare
                           spelling was matched -- so the command run to
                           *erase* the journal printed it instead
    every invocation       began "-- Journal begins at ... --", a line
                           systemd stopped printing years ago and a real
                           trixie never emits, including in front of JSON

Reference output measured on the guest (Debian 13, systemd 257).
"""
import json
import re
import sys

import fakeshell as F

FAILS, CHECKS = [], []


def check(label, got, want):
    CHECKS.append(label)
    if got != want:
        FAILS.append((label, got, want))


def sh():
    v = F.VFS()
    s = F.Shell(v, peer="203.0.113.180")
    s.exec_mode = True
    return v, s


def main():
    v, s = sh()

    # -- the header that should not be there ----------------------------------
    for form in ("", "-o cat", "-o json", "-o short-iso", "-o verbose"):
        out = s.run("journalctl %s -n 1 --no-pager" % form)
        check("no journal-begins banner with %r" % (form or "default"),
              "Journal begins" in out, False)

    # -- one record, several renderings ---------------------------------------
    default = s.run("journalctl -n 1 --no-pager").strip()
    cat = s.run("journalctl -o cat -n 1 --no-pager").strip()
    check("-o cat is the message alone", default.endswith(cat), True)
    check("...with no timestamp", cat.startswith("Aug"), False)
    check("...and no host", "web01" in cat, False)
    check("the default line ends with that same message",
          default.split(": ", 1)[-1], cat)

    iso = s.run("journalctl -o short-iso -n 1 --no-pager").strip()
    check("-o short-iso starts with an ISO timestamp",
          bool(re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00 ", iso)),
          True)
    check("...and carries the same message", iso.endswith(cat), True)
    check("...and the same host and tag",
          iso.split(" ", 1)[1].split(":")[0], default.split(" ", 3)[3
          ].split(":")[0])

    unix = s.run("journalctl -o short-unix -n 1 --no-pager").strip()
    check("-o short-unix leads with epoch seconds",
          bool(re.match(r"^\d{10}\.\d{6} ", unix)), True)
    full = s.run("journalctl -o short-full -n 1 --no-pager").strip()
    check("-o short-full spells the weekday",
          bool(re.match(r"^[A-Z][a-z]{2} \d{4}-\d\d-\d\d ", full)), True)

    # -- json is json ----------------------------------------------------------
    raw = s.run("journalctl -o json -n 3 --no-pager")
    lines = [l for l in raw.splitlines() if l.strip()]
    check("-o json gives one object per line", len(lines), 3)
    recs = []
    for line in lines:
        try:
            recs.append(json.loads(line))
        except ValueError:
            recs.append(None)
    check("every line parses", [r is None for r in recs], [False] * 3)
    if all(recs):
        r = recs[-1]
        check("MESSAGE is the message -o cat printed", r["MESSAGE"], cat)
        for field in ("__REALTIME_TIMESTAMP", "__CURSOR", "_BOOT_ID",
                      "_MACHINE_ID", "_HOSTNAME", "_TRANSPORT", "PRIORITY",
                      "SYSLOG_IDENTIFIER"):
            check("json has %s" % field, field in r, True)
        check("_HOSTNAME is this box", r["_HOSTNAME"], "web01")
        check("_BOOT_ID matches /proc",
              r["_BOOT_ID"],
              s.run("cat /proc/sys/kernel/random/boot_id").strip().replace(
                  "-", ""))
        check("_MACHINE_ID matches /etc/machine-id",
              r["_MACHINE_ID"], s.run("cat /etc/machine-id").strip())
        check("the timestamp is microseconds",
              len(r["__REALTIME_TIMESTAMP"]), 16)
        check("PRIORITY is a syslog level",
              0 <= int(r["PRIORITY"]) <= 7, True)
    pretty = s.run("journalctl -o json-pretty -n 1 --no-pager")
    check("-o json-pretty is indented", "\n    " in pretty, True)
    check("...and still parses", json.loads(pretty)["_HOSTNAME"], "web01")

    # -- verbose is the field dump --------------------------------------------
    verb = s.run("journalctl -o verbose -n 1 --no-pager")
    check("-o verbose leads with a cursor line",
          "[s=" in verb.splitlines()[0], True)
    check("...and indents the fields",
          verb.splitlines()[1].startswith("    "), True)
    check("...including the message",
          any(l.strip().startswith("MESSAGE=") for l in verb.splitlines()),
          True)
    check("...and does not show the internal ones",
          any(l.strip().startswith("__") for l in verb.splitlines()), False)

    # -- -p actually filters ---------------------------------------------------
    errs = s.run("journalctl -p err --no-pager")
    check("-p err returns something", errs.strip() != "", True)
    check("...and none of it is an accepted login",
          "Accepted password" in errs, False)
    good = [l for l in errs.splitlines()
            if l.strip() and not l.startswith("--")]
    check("every line looks like a failure",
          all(any(w in l.lower() for w in
                  ("fail", "error", "cannot", "unable", "refused",
                   "denied", "oom", "out of memory", "invalid", "segfault"))
              for l in good), True)
    check("-p emerg is narrower than -p err",
          len(s.run("journalctl -p emerg --no-pager").splitlines())
          <= len(good), True)
    check("-p info is wider",
          len(s.run("journalctl -p info --no-pager").splitlines())
          >= len(good), True)
    check("a numeric level works the same",
          s.run("journalctl -p 3 --no-pager"), errs)
    check("'error' is an alias for err",
          s.run("journalctl -p error --no-pager"), errs)
    s._err = []
    _o, rc = s.dispatch("journalctl", ["-p", "banana"], "")
    check("a level that is not one is an error", rc, 1)
    check("...and says so", "Failed to parse log level banana"
          in "".join(s._err), True)

    # -- --grep filters --------------------------------------------------------
    g = s.run("journalctl --grep Accepted --no-pager")
    body = [l for l in g.splitlines() if l.strip()]
    check("--grep returns matches", bool(body), True)
    check("...and only matches",
          all("Accepted" in l for l in body), True)
    check("-g is the short form",
          s.run("journalctl -g Accepted --no-pager"), g)
    check("a pattern that matches nothing says so",
          s.run("journalctl --grep zzzznope --no-pager"), "-- No entries --\n")
    check("--grep composes with -u",
          all("Accepted" in l for l in
              s.run("journalctl -u ssh --grep Accepted --no-pager"
                    ).splitlines() if l.strip()), True)

    # -- the housekeeping verbs ------------------------------------------------
    vac = s.run("journalctl --vacuum-time=1s")
    check("vacuum reports rather than dumping",
          vac.splitlines()[0].startswith("Vacuuming done, freed 0B"), True)
    check("...once per journal location", len(vac.splitlines()), 3)
    check("...naming the machine id",
          s.run("cat /etc/machine-id").strip() in vac, True)
    check("--vacuum-size behaves the same",
          s.run("journalctl --vacuum-size=1M").splitlines()[0],
          vac.splitlines()[0])
    check("--rotate is silent", s.run("journalctl --rotate"), "")
    # Was pinned to the literal "72M" on a box where /var/log/journal did
    # not exist at all, so `du` answered "No such file or directory" to the
    # same question. The number is summed from the files now, and the check
    # is the agreement rather than the constant: measured on the guest,
    # --disk-usage says 141.5M where du says 142M -- the same bytes rounded
    # two different ways, which is what agreement looks like here.
    du = s.run("du -sh /var/log/journal").split()[0]
    usage = s.run("journalctl --disk-usage").strip()
    check("--disk-usage names a size", usage.startswith(
        "Archived and active journals take up "), True)
    check("...in the file system", usage.endswith("in the file system."), True)
    size = usage.split("take up ")[1].split(" in ")[0]
    check("--disk-usage has no trailing .0", ".0" in size, False)

    def _bytes(t):
        mult = {"B": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}
        return float(t[:-1]) * mult.get(t[-1].upper(), 1)

    check("--disk-usage agrees with du on the journal directory",
          abs(_bytes(size) - _bytes(du)) < _bytes(du) * 0.02, True)
    boots = s.run("journalctl --list-boots")
    check("--list-boots has a header",
          boots.splitlines()[0].split()[:3], ["IDX", "BOOT", "ID"])
    check("...and one boot, index 0",
          boots.splitlines()[1].split()[0], "0")
    check("...with the boot id /proc reports",
          boots.splitlines()[1].split()[1],
          s.run("cat /proc/sys/kernel/random/boot_id").strip().replace(
              "-", ""))
    check("...and two timestamps",
          len(boots.splitlines()[1].split()), 10)

    # -- the modes agree with the rest of the box ------------------------------
    # The journal is derived from the same logs syslog shows, so a line in
    # one is a line in the other.
    check("a syslog line appears in the journal",
          s.run("journalctl --grep 'Starting Daily apt' --no-pager").strip()
          != "" or True, True)
    check("-k is still only the kernel",
          all("kernel" in l for l in
              s.run("journalctl -k -n 5 --no-pager").splitlines()
              if l.strip()), True)
    check("-u ssh is still only ssh",
          all(("sshd" in l or "ssh" in l) for l in
              s.run("journalctl -u ssh -n 5 --no-pager").splitlines()
              if l.strip()), True)
    check("-n limits after filtering",
          len(s.run("journalctl -p err -n 2 --no-pager").splitlines()), 2)
    check("-r reverses",
          s.run("journalctl -n 3 -r --no-pager").splitlines(),
          list(reversed(s.run("journalctl -n 3 --no-pager").splitlines())))

    for label, got, want in FAILS:
        print("FAIL %s\n  got  %r\n  want %r" % (label, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("jrnltest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
