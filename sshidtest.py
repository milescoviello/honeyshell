#!/usr/bin/env python3
"""What does the box say about its own SSH identity, and about keys?

An attacker arrives holding one piece of ground truth: the host key their
own client just recorded. Comparing it with /etc/ssh is a one-command
check, and everything around that check was broken.

  - All three private host keys were a 36-byte stub. A real ed25519 key
    file is 399 bytes, ecdsa 505, rsa 1823 -- `ls -l /etc/ssh` shows that
    without anyone having to read them. They are the right size now, and
    still not keys: the real ones are the honeypot's own and must never be
    readable from inside it.
  - `ssh-keygen` parsed -l and -F and nothing else. Every other form fell
    through to a three-line "Generating public/private rsa key pair" that
    wrote no files at all:
      * `ssh-keygen -t ed25519 -f /tmp/k -N ''` -- how an attacker makes
        the key they are about to install -- claimed to have saved
        /root/.ssh/id_rsa and left nothing anywhere.
      * `ssh-keygen -y -f stolen.key`, which reads a private key and prints
        its public half, *generated* a key instead.
      * so did `ssh-keygen -R host`, which is supposed to edit known_hosts.
      * `ssh-keygen -lf` on a private key said "is not a public key file".
  - `ssh-keyscan localhost` printed nothing, on a box whose `ss -tlnp`
    shows sshd listening on 22.

Formats and file sizes were measured on the real Debian 13 cloud guest, and
the host-key fingerprints are checked against the ones the SSH layer
publishes at startup -- the same check an attacker makes against their own
known_hosts.

Run from `honeypot/`, or on the guest.
"""

import base64
import hashlib
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def sh(user="root"):
    s = fs.Shell(fs.VFS(), peer="203.0.113.77", user=user)
    s.exec_mode = True
    return s


def run(s, cmd, stdin=""):
    out = s.run(cmd, stdin)
    err = "".join(s._err)
    s._err.clear()
    return (out + err), s.last_rc


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-52s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


def fp_of(line):
    blob = base64.b64decode(line.split()[1] + "===")
    return "SHA256:" + base64.b64encode(
        hashlib.sha256(blob).digest()).decode().rstrip("=")


# --- the host keys ----------------------------------------------------------

def t_the_pub_files_are_the_keys_the_server_serves():
    """The comparison an attacker makes against their own known_hosts."""
    published = dict(fs.HOST_KEY_PUBS or {})
    s = sh()
    if not published:
        # Standalone, with no SSH layer to publish them: check the wiring
        # instead, by publishing a key and rebuilding.
        fs.HOST_KEY_PUBS = {
            "ssh_host_ed25519_key":
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH8fD2mQ9vXcR4tLpZ6w"
                "B3nK1sJ7gY0aM5xQ2vN8bZeT root@web01\n"}
        try:
            s2 = sh()
            o, _ = run(s2, "cat /etc/ssh/ssh_host_ed25519_key.pub")
            eq("a published host key reaches /etc/ssh",
               o.strip(), fs.HOST_KEY_PUBS["ssh_host_ed25519_key"].strip())
            o2, _ = run(s2, "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub")
            eq("and its fingerprint is the fingerprint of that key",
               o2.split()[1],
               fp_of(fs.HOST_KEY_PUBS["ssh_host_ed25519_key"]))
        finally:
            fs.HOST_KEY_PUBS = published
        return
    for name, line in published.items():
        o, _ = run(s, "cat /etc/ssh/%s.pub" % name)
        eq("/etc/ssh/%s.pub is what the transport serves" % name,
           o.strip(), line.strip())
        o2, _ = run(s, "ssh-keygen -lf /etc/ssh/%s.pub" % name)
        eq("...and ssh-keygen agrees on its fingerprint",
           o2.split()[1], fp_of(line))


def t_private_host_keys_look_like_key_files():
    s = sh()
    want = {"ssh_host_ed25519_key": 399, "ssh_host_ecdsa_key": 505,
            "ssh_host_rsa_key": 1823}
    for name, size in want.items():
        o, _ = run(s, "stat -c '%s %a' /etc/ssh/" + name)
        got, mode = o.split()
        eq("%s is %d bytes" % (name, size), int(got), size)
        eq("...and mode 600", mode, "600")
        o2, _ = run(s, "head -1 /etc/ssh/%s" % name)
        eq("...and opens like an OpenSSH key", o2.strip(),
           "-----BEGIN OPENSSH PRIVATE KEY-----")
        o3, _ = run(s, "tail -1 /etc/ssh/%s" % name)
        eq("...and closes like one", o3.strip(),
           "-----END OPENSSH PRIVATE KEY-----")


def t_y_prints_the_public_half():
    s = sh()
    o, rc = run(s, "ssh-keygen -y -f /etc/ssh/ssh_host_ed25519_key")
    eq("rc", rc, 0)
    p, _ = run(s, "cat /etc/ssh/ssh_host_ed25519_key.pub")
    eq("-y prints the matching public key",
       " ".join(o.split()[:2]), " ".join(p.split()[:2]))
    check("and does not generate anything",
          "Generating" not in o, o[:60])
    o2, rc2 = run(s, "ssh-keygen -y -f /etc/ssh/nosuchkey")
    eq("a missing key is an error, not a new key", rc2, 255)
    check("with ssh-keygen's wording", "Load key" in o2, o2[:70])


def t_lf_fingerprints_a_private_key_too():
    s = sh()
    a, rc = run(s, "ssh-keygen -lf /etc/ssh/ssh_host_rsa_key")
    eq("rc", rc, 0)
    b, _ = run(s, "ssh-keygen -lf /etc/ssh/ssh_host_rsa_key.pub")
    eq("the pair has one fingerprint", a.split()[1], b.split()[1])
    check("and the bit count is the key's", a.split()[0] in ("2048", "3072"),
          a[:40])


# --- making a key -----------------------------------------------------------

def t_keygen_writes_the_files_it_says_it_wrote():
    s = sh()
    o, rc = run(s, "ssh-keygen -t ed25519 -f /tmp/att -N ''")
    eq("rc", rc, 0)
    check("it says where it saved them",
          "/tmp/att" in o and "/tmp/att.pub" in o, o[:120])
    for f, mode in (("/tmp/att", "600"), ("/tmp/att.pub", "644")):
        o2, rc2 = run(s, "stat -c %%a %s" % f)
        eq("%s exists with mode %s" % (f, mode), (o2.strip(), rc2),
           (mode, 0))
    o3, _ = run(s, "cat /tmp/att.pub")
    check("the public key is an ed25519 one",
          o3.startswith("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5"), o3[:40])
    o4, _ = run(s, "ssh-keygen -lf /tmp/att.pub")
    check("the printed fingerprint is the file's",
          o4.split()[1] in o, "%s vs %s" % (o4.split()[1], o[:200]))
    eq("...and it is 256 bits", o4.split()[0], "256")
    o5, _ = run(s, "ssh-keygen -y -f /tmp/att")
    eq("-y round-trips the pair", o5.strip(), o3.strip())


def t_keygen_honours_the_type_it_was_asked_for():
    s = sh()
    run(s, "ssh-keygen -t rsa -b 2048 -f /tmp/r -N '' -q")
    o, _ = run(s, "cat /tmp/r.pub")
    check("an rsa key is an rsa key", o.startswith("ssh-rsa "), o[:30])
    o2, _ = run(s, "ssh-keygen -lf /tmp/r.pub")
    eq("of the size asked for", o2.split()[0], "2048")
    o3, _ = run(s, "stat -c %s /tmp/r")
    eq("and the private file is the size a 2048-bit key makes",
       o3.strip(), "1823")
    run(s, "ssh-keygen -t ecdsa -f /tmp/c -N '' -q")
    o4, _ = run(s, "cat /tmp/c.pub")
    check("an ecdsa key names its curve",
          o4.startswith("ecdsa-sha2-nistp256 "), o4[:30])


def t_quiet_is_quiet_and_the_default_path_is_the_users():
    s = sh()
    o, rc = run(s, "ssh-keygen -t ed25519 -f /tmp/q -N '' -q")
    eq("-q prints nothing", (o.strip(), rc), ("", 0))
    d = sh(user="deploy")
    run(d, "ssh-keygen -t ed25519 -N '' -q")
    o2, rc2 = run(d, "ls /home/deploy/.ssh/id_ed25519 "
                     "/home/deploy/.ssh/id_ed25519.pub")
    eq("with no -f it lands in the caller's own ~/.ssh", rc2, 0)
    check("both halves", len(o2.split()) == 2, o2)


def t_an_existing_key_is_not_silently_replaced():
    s = sh()
    run(s, "ssh-keygen -t ed25519 -f /tmp/once -N '' -q")
    first, _ = run(s, "cat /tmp/once.pub")
    o, rc = run(s, "ssh-keygen -t ed25519 -f /tmp/once -N ''")
    eq("it asks before overwriting", rc, 1)
    check("with ssh-keygen's prompt", "Overwrite (y/n)?" in o, o[:80])
    again, _ = run(s, "cat /tmp/once.pub")
    eq("and the key is untouched", again, first)


def t_generating_a_key_is_recorded():
    """A key made on the box is the key they mean to install."""
    seen = []
    s = fs.Shell(fs.VFS(), peer="203.0.113.77",
                 log=lambda **kw: seen.append(kw))
    s.exec_mode = True
    run(s, "ssh-keygen -t ed25519 -f /tmp/log -N '' -q")
    evs = [e for e in seen if e.get("event") == "ssh_keygen"]
    eq("one event", len(evs), 1)
    eq("naming the file", evs[0].get("path"), "/tmp/log")
    check("and carrying the public key",
          evs[0].get("pubkey", "").startswith("ssh-ed25519 "),
          evs[0].get("pubkey", "")[:40])


# --- known_hosts ------------------------------------------------------------

def t_known_hosts_search_and_removal():
    s = sh()
    run(s, "mkdir -p /root/.ssh; printf '10.8.0.6 ssh-ed25519 AAAAC3Nza"
           "C1lZDI1NTE5AAAAIH8fD2mQ9vXcR4tLpZ6wB3nK1sJ7gY0aM5xQ2vN8bZeT\\n"
           "1.2.3.4 ssh-rsa AAAAB3NzaC1yc2E=\\n' > /root/.ssh/known_hosts")
    o, rc = run(s, "ssh-keygen -F 10.8.0.6")
    eq("-F finds a host", rc, 0)
    check("and prints the line", "ssh-ed25519" in o, o[:80])
    o2, rc2 = run(s, "ssh-keygen -F 9.9.9.9")
    eq("a host that is not there is rc 1", rc2, 1)
    eq("and prints nothing", o2.strip(), "")
    o3, rc3 = run(s, "ssh-keygen -R 10.8.0.6")
    eq("-R rc", rc3, 0)
    check("it says what it removed", "found: line 1" in o3, o3[:80])
    o4, _ = run(s, "cat /root/.ssh/known_hosts")
    check("the host is gone", "10.8.0.6" not in o4, o4[:80])
    check("and the other one is not", "1.2.3.4" in o4, o4[:80])
    check("nothing was generated", "Generating" not in o3, o3[:60])


# --- keyscan ----------------------------------------------------------------

def t_keyscan_answers_for_this_host():
    s = sh()
    o, rc = run(s, "ssh-keyscan localhost")
    eq("rc", rc, 0)
    lines = [l for l in o.splitlines() if l.strip()]
    check("it announces the banner",
          lines and lines[0].startswith("# localhost:22 SSH-2.0-OpenSSH"),
          lines[:1])
    keys = [l for l in lines if not l.startswith("#")]
    eq("three keys, as sshd serves", len(keys), 3)
    for k in keys:
        pubs, _ = run(s, "cat /etc/ssh/ssh_host_*.pub")
        check("the key it prints is one of ours",
              k.split()[2] in pubs, k[:60])
    o2, _ = run(s, "ssh-keyscan -t ed25519 127.0.0.1")
    ks = [l for l in o2.splitlines() if not l.startswith("#") and l.strip()]
    eq("-t selects one", len(ks), 1)
    check("the one asked for", ks[0].split()[1] == "ssh-ed25519", ks[0][:40])


def t_keyscan_does_not_reach_out():
    s = sh()
    o, rc = run(s, "ssh-keyscan 203.0.113.200")
    eq("a host that is not us prints nothing", o.strip(), "")
    eq("and exits 0, as ssh-keyscan does when it finds nothing", rc, 0)


def t_the_banner_is_the_one_on_the_wire():
    s = sh()
    o, _ = run(s, "ssh-keyscan localhost")
    banner = o.splitlines()[0].split(" ", 2)[2]
    eq("keyscan quotes the served banner", banner, fs.SSH_BANNER)
    v, _ = run(s, "ssh -V")
    check("and ssh -V names the same OpenSSH",
          v.split()[0].replace("OpenSSH_", "") in banner, v[:60])


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("t_")]


def main():
    for t in TESTS:
        try:
            t()
        except Exception as exc:                              # noqa: BLE001
            check(t.__name__, False, "crashed: %r" % (exc,))
    print("passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL[:10]))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
