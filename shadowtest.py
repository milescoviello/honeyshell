r"""The hash in /etc/shadow and the password that opens the account.

Sixty-ninth coherence sweep. `cat /etc/shadow` and feed it to john is
standard post-exploitation -- it is the reason /etc/shadow is worth
reading at all -- so: does the hash this box publishes for an account
correspond to the password that actually opens it?

It did not. Both seeded hashes were invented strings:

    root    $y$j9T$Fq2Yx.Kk1mQpZ8vHn3wLd1$8kQ2mNvXcR7pLwT4yBnMzE1sK9dF3gH6...
    deploy  $y$j9T$Bn4Rt.Wq7xLmK2pV9sHc80$3mZxQ8vN1kR6tY2wB5nL9cP4jD7fG0hS...

Neither verifies against anything, and deploy's body was 42 characters
where a yescrypt body is always 43 -- not merely wrong but malformed, so
a cracker would reject the line rather than fail to crack it. root's
password is 123456 and deploy's is deploy123; an attacker who has just
logged in with one and then reads the hash is looking at a direct
contradiction.

Both are real now, generated with libxcrypt against the salts already
published here and checked to round-trip, so cracking /etc/shadow yields
exactly the credentials that work. The box says ENCRYPT_METHOD YESCRYPT
in login.defs and `pam_unix.so obscure yescrypt` in PAM, and the format
matches that.

The runtime generator was worse in a different way. It derived the salt
from the plaintext, so two accounts given the same password came out
byte-identical -- something a random salt makes impossible and the first
thing anyone notices in a shadow file -- and both halves came from one
sha256 stream, so the body visibly repeated the salt. The salt is random
now and the body is derived from salt+password.

What is deliberately still not true: a password set at runtime produces a
well-formed hash that does not verify. The Python on the target has no
crypt module -- removed in 3.13 -- and yescrypt is not something to
reimplement in a fake shell. Nobody cracks a hash for a password they
just chose; the hashes that matter are the two this box accepts, and
those are real.

Run from `honeypot/`, or on the guest.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []

# What this box accepts, per ssh_honeypot.REAL_CREDS.
WORKING = {"root": "123456", "deploy": "deploy123"}

try:
    import crypt as _crypt
except ImportError:                                            # py3.13+
    _crypt = None


def shell():
    s = fs.Shell(fs.VFS(), user="root", peer="203.0.113.77")
    s.exec_mode = True
    return s


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-48s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


def out(s, cmd):
    o = s.run(cmd)
    o += "".join(s._err)
    s._err.clear()
    return o.strip()


def hash_of(s, user):
    return out(s, "grep '^%s:' /etc/shadow | cut -d: -f2" % user)


# -- the hashes that matter are real -------------------------------------

def t_the_working_credentials_verify():
    """The whole point. Skipped where crypt is unavailable, and the suite
    says so rather than passing quietly."""
    if _crypt is None:
        check("crypt module available to verify", False,
              "no crypt module here; run this suite on a host that has one")
        return
    s = shell()
    for user, pw in WORKING.items():
        h = hash_of(s, user)
        check("%s hash present" % user, h.startswith("$y$"), h[:20])
        eq("%s verifies against %r" % (user, pw), _crypt.crypt(pw, h), h)


def t_a_wrong_password_does_not_verify():
    if _crypt is None:
        return
    s = shell()
    h = hash_of(s, "root")
    check("wrong password rejected", _crypt.crypt("hunter2", h) != h, "")


def t_the_format_is_well_formed():
    s = shell()
    for user in WORKING:
        h = hash_of(s, user)
        parts = h.split("$")
        eq("%s prefix" % user, parts[1], "y")
        eq("%s params" % user, parts[2], "j9T")
        eq("%s salt length" % user, len(parts[3]), 22)
        # 43 is not a stylistic choice: a yescrypt body is always 43 chars,
        # and deploy's was 42, which makes the line malformed rather than
        # merely uncrackable.
        eq("%s body length" % user, len(parts[4]), 43)
        check("%s alphabet" % user,
              re.fullmatch(r"[./0-9A-Za-z]+", parts[3] + parts[4]) is not None,
              h)


def t_the_hash_matches_the_declared_method():
    s = shell()
    eq("login.defs", out(s, "awk '/^ENCRYPT_METHOD/{print $2}' /etc/login.defs"),
       "YESCRYPT")
    check("pam agrees", "yescrypt" in out(s, "grep pam_unix /etc/pam.d/"
                                          "common-password"), "")
    for user in WORKING:
        check("%s uses $y$" % user, hash_of(s, user).startswith("$y$"), "")


def t_locked_accounts_stay_locked():
    """Only the two accounts that work carry a hash."""
    s = shell()
    for user in ("daemon", "bin", "sys", "www-data", "mysql"):
        h = hash_of(s, user)
        check("%s has no usable hash" % user, h in ("*", "!", "!*"), h)


def t_shadow_is_not_world_readable():
    s = shell()
    eq("mode", out(s, "stat -c '%a' /etc/shadow"), "640")
    eq("owner", out(s, "stat -c '%U:%G' /etc/shadow"), "root:shadow")


# -- a runtime-set password ----------------------------------------------

def t_the_same_password_gives_different_hashes():
    """A random salt makes a collision impossible; a salt derived from the
    plaintext makes it certain."""
    s = shell()
    out(s, "useradd -m alice; useradd -m bob")
    out(s, "echo 'alice:samepass' | chpasswd")
    out(s, "echo 'bob:samepass' | chpasswd")
    a, b = hash_of(s, "alice"), hash_of(s, "bob")
    check("both set", a.startswith("$y$") and b.startswith("$y$"),
          "%r %r" % (a[:16], b[:16]))
    check("and they differ", a != b, a)


def t_setting_the_same_password_twice_rerolls():
    s = shell()
    out(s, "useradd -m alice")
    out(s, "echo 'alice:pw1' | chpasswd")
    first = hash_of(s, "alice")
    out(s, "echo 'alice:pw1' | chpasswd")
    check("new salt each time", hash_of(s, "alice") != first, first)


def t_the_body_does_not_repeat_the_salt():
    s = shell()
    out(s, "useradd -m alice; echo 'alice:whatever' | chpasswd")
    h = hash_of(s, "alice")
    salt, body = h.split("$")[3], h.split("$")[4]
    check("no overlap", salt not in body, h)
    check("salt is not a slice of the body", body[:22] != salt, h)


def t_a_runtime_hash_is_well_formed():
    s = shell()
    out(s, "useradd -m alice; echo 'alice:whatever' | chpasswd")
    parts = hash_of(s, "alice").split("$")
    eq("prefix", parts[1], "y")
    eq("salt length", len(parts[3]), 22)
    eq("body length", len(parts[4]), 43)
    check("alphabet",
          re.fullmatch(r"[./0-9A-Za-z]+", parts[3] + parts[4]) is not None,
          hash_of(s, "alice"))


def t_the_plaintext_does_not_appear_in_the_hash():
    s = shell()
    out(s, "useradd -m alice; echo 'alice:CorrectHorseBattery' | chpasswd")
    h = hash_of(s, "alice")
    check("no plaintext", "CorrectHorse" not in h, h)


def t_passwd_d_clears_it():
    s = shell()
    out(s, "useradd -m alice; echo 'alice:pw' | chpasswd")
    check("set", hash_of(s, "alice").startswith("$y$"), "")
    out(s, "passwd -d alice")
    eq("cleared", hash_of(s, "alice"), "")


def t_passwd_l_locks_it():
    s = shell()
    out(s, "useradd -m alice; echo 'alice:pw' | chpasswd")
    h = hash_of(s, "alice")
    out(s, "passwd -l alice")
    locked = hash_of(s, "alice")
    check("prefixed with !", locked.startswith("!"), locked[:8])
    check("hash kept underneath", h in locked, locked[:24])


# -- the file stays coherent ---------------------------------------------

def t_every_passwd_user_has_a_shadow_line():
    s = shell()
    pw = sorted(out(s, "cut -d: -f1 /etc/passwd").split())
    sh = sorted(out(s, "cut -d: -f1 /etc/shadow").split())
    eq("same users", sh, pw)


def t_a_new_user_gets_a_locked_shadow_line():
    s = shell()
    out(s, "useradd -m carol")
    eq("locked until a password is set", hash_of(s, "carol"), "!")


TESTS = [t_the_working_credentials_verify, t_a_wrong_password_does_not_verify,
         t_the_format_is_well_formed, t_the_hash_matches_the_declared_method,
         t_locked_accounts_stay_locked, t_shadow_is_not_world_readable,
         t_the_same_password_gives_different_hashes,
         t_setting_the_same_password_twice_rerolls,
         t_the_body_does_not_repeat_the_salt, t_a_runtime_hash_is_well_formed,
         t_the_plaintext_does_not_appear_in_the_hash, t_passwd_d_clears_it,
         t_passwd_l_locks_it, t_every_passwd_user_has_a_shadow_line,
         t_a_new_user_gets_a_locked_shadow_line]


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
