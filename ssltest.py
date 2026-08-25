#!/usr/bin/env python3
"""Does the box agree with itself about hashing, encoding and its CA store?

Chosen because the captured RedTail setup.sh opens with get_random_string(),
which branches on `command -v openssl` and then calls `openssl rand -base64
256 | tr -dc 'A-Za-z0-9' | head -c $len`. The payload is the specification.

  - openssl implemented exactly two subcommands, version and rand.
    Everything else -- dgst, md5, sha256, base64, enc, passwd, x509,
    ciphers, s_client, help -- returned an empty string and rc 0. Silent
    success is the worst answer a honeypot can give, because the caller
    cannot tell. `openssl dgst -sha256 f` printed nothing while `sha256sum
    f` answered: two commands, one question, one of them mute.
  - `dpkg -l` said ca-certificates 20250419 was installed and /etc/ssl did
    not exist at all -- the package's entire content is that directory.
    /usr/lib/ssl, which `openssl version -d` names as OPENSSLDIR, was
    missing too, and `openssl version -d` ignored the -d and printed the
    version.
  - update-ca-certificates and c_rehash were unimplemented stock binaries
    answering "missing operand".
  - Found on the way: `xargs -I{} sh -c "..."` parsed xargs' options across
    the whole line, so sh lost its -c and was handed the script as argv[0].

Run from `honeypot/`, or on the guest.
"""

import hashlib
import os
import re
import sys

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


def t_openssl_dgst_agrees_with_the_coreutils_tools():
    """The contradiction this sweep started from."""
    s = sh()
    for alg, tool, label in (("md5", "md5sum", "MD5"),
                             ("sha1", "sha1sum", "SHA1"),
                             ("sha256", "sha256sum", "SHA2-256"),
                             ("sha512", "sha512sum", "SHA2-512")):
        for target in ("/etc/hostname", "/etc/os-release"):
            a, rca = run(s, "openssl dgst -%s %s" % (alg, target))
            b, rcb = run(s, "%s %s" % (tool, target))
            eq("openssl dgst -%s %s rc" % (alg, target), rca, 0)
            eq("%s %s rc" % (tool, target), rcb, 0)
            m = re.match(r"^%s\(%s\)= ([0-9a-f]+)$" % (re.escape(label),
                                                       re.escape(target)),
                         a.strip())
            check("openssl dgst -%s output shape" % alg, m, repr(a[:70]))
            if m:
                eq("openssl and %s agree on %s" % (tool, target),
                   m.group(1), b.split()[0])
        # `openssl sha256 f` is the same thing spelled differently.
        c, _ = run(s, "openssl %s /etc/hostname" % alg)
        d, _ = run(s, "openssl dgst -%s /etc/hostname" % alg)
        eq("openssl %s == openssl dgst -%s" % (alg, alg), c, d)


def t_digest_of_stdin_is_labelled_stdin():
    s = sh()
    o, rc = run(s, "echo -n abc | openssl dgst -sha256")
    eq("stdin digest rc", rc, 0)
    want = hashlib.sha256(b"abc").hexdigest()
    eq("stdin digest value", o.strip(), "SHA2-256(stdin)= " + want)
    o2, _ = run(s, "echo -n abc | sha256sum")
    eq("and sha256sum agrees", o2.split()[0], want)


def t_base64_round_trips_and_matches_coreutils():
    s = sh()
    for text in ("abc", "hello world", "a"):
        a, rca = run(s, "printf %%s '%s' | openssl base64" % text)
        b, rcb = run(s, "printf %%s '%s' | base64" % text)
        eq("openssl base64 rc", rca, 0)
        eq("openssl base64 matches coreutils base64 for %r" % text,
           a.strip(), b.strip())
        c, rcc = run(s, "printf %%s '%s' | openssl base64 | openssl base64 -d"
                     % text)
        eq("openssl base64 round trip for %r" % text, c, text)
        d, _ = run(s, "printf %%s '%s' | openssl base64 | base64 -d" % text)
        eq("cross round trip for %r" % text, d, text)
    o, rc = run(s, "echo 'not!valid!base64!' | openssl base64 -d")
    eq("invalid base64 is an error", rc, 1)


def t_unknown_subcommands_are_refused_not_silently_accepted():
    s = sh()
    for bad in ("foobar", "notacommand", "dgstx"):
        o, rc = run(s, "openssl %s" % bad)
        eq("openssl %s rc" % bad, rc, 1)
        check("openssl %s message" % bad,
              "Invalid command '%s'" % bad in o, o[:80])
    # And no subcommand may return empty output with rc 0.
    for sub in ("version", "ciphers", "help", "rand -hex 4",
                "dgst -sha256 /etc/hostname", "x509 -noout -subject -in "
                "/etc/ssl/certs/ISRG_Root_X1.pem"):
        o, rc = run(s, "openssl " + sub)
        check("openssl %s says something" % sub.split()[0], o.strip() != "",
              "empty, rc=%d" % rc)


def t_openssl_version_flags():
    s = sh()
    o, rc = run(s, "openssl version")
    eq("openssl version rc", rc, 0)
    m = re.match(r"OpenSSL (\S+) ", o)
    check("version line shape", m, o[:60])
    pkg, _ = run(s, "dpkg-query -W -f '${Version}' openssl")
    if m:
        check("openssl version matches the openssl package (%s)" % pkg.strip(),
              m.group(1) in pkg, "%r vs %r" % (m.group(1), pkg))
    o, rc = run(s, "openssl version -d")
    eq("openssl version -d rc", rc, 0)
    m = re.match(r'OPENSSLDIR: "([^"]+)"', o.strip())
    check("version -d prints OPENSSLDIR, not the version", m, o[:60])
    if m:
        o2, rc2 = run(s, "test -d %s && echo yes" % m.group(1))
        eq("OPENSSLDIR exists", (o2.strip(), rc2), ("yes", 0))
        o3, _ = run(s, "readlink %s/certs" % m.group(1))
        eq("OPENSSLDIR/certs points at /etc/ssl/certs", o3.strip(),
           "/etc/ssl/certs")
    o, _ = run(s, "openssl version -a")
    check("version -a is multi-line", len(o.strip().splitlines()) > 4, o[:60])


def t_the_ca_store_dpkg_claims_actually_exists():
    s = sh()
    o, rc = run(s, "dpkg-query -W -f '${Version}' ca-certificates")
    eq("ca-certificates is installed", rc, 0)
    for p in ("/etc/ssl", "/etc/ssl/certs", "/etc/ssl/private",
              "/usr/share/ca-certificates/mozilla", "/usr/lib/ssl",
              "/etc/ssl/openssl.cnf", "/etc/ca-certificates.conf",
              "/etc/ssl/certs/ca-certificates.crt"):
        o, rc = run(s, "test -e %s && echo yes" % p)
        eq("%s exists" % p, (o.strip(), rc), ("yes", 0))
    o, _ = run(s, "ls -ld /etc/ssl/private")
    check("private keys are not world readable", o.startswith("drwx------"),
          o[:40])


def t_bundle_pem_files_and_conf_all_count_the_same():
    s = sh()
    n_bundle, _ = run(s, "grep -c 'BEGIN CERTIFICATE' "
                         "/etc/ssl/certs/ca-certificates.crt")
    n_pem, _ = run(s, "ls /etc/ssl/certs/*.pem | wc -l")
    n_src, _ = run(s, "ls /usr/share/ca-certificates/mozilla/*.crt | wc -l")
    n_conf, _ = run(s, "grep -c '^mozilla/' /etc/ca-certificates.conf")
    n_hash, _ = run(s, "ls /etc/ssl/certs/*.0 | wc -l")
    vals = {"bundle": n_bundle.strip(), "pem links": n_pem.strip(),
            "mozilla .crt": n_src.strip(), "conf lines": n_conf.strip(),
            "hash links": n_hash.strip()}
    eq("all five counts agree", len(set(vals.values())), 1)
    if len(set(vals.values())) != 1:
        for k, v in vals.items():
            print("      %-14s %s" % (k, v))
    o, _ = run(s, "update-ca-certificates")
    m = re.search(r"(\d+) added, 0 removed", o)
    check("update-ca-certificates reports a count", m, o[:80])
    if m:
        eq("and it is the same count", m.group(1), n_pem.strip())


def t_each_pem_link_resolves_and_holds_a_certificate():
    s = sh()
    o, _ = run(s, "ls /etc/ssl/certs/*.pem | head -6")
    for path in o.split():
        tgt, rc = run(s, "readlink -f %s" % path)
        eq("%s resolves" % path, rc, 0)
        check("%s points into /usr/share/ca-certificates" % path,
              tgt.strip().startswith("/usr/share/ca-certificates/mozilla/"),
              tgt.strip())
        head, _ = run(s, "head -1 %s" % path)
        eq("%s starts with a PEM header" % path, head.strip(),
           "-----BEGIN CERTIFICATE-----")
        tail, _ = run(s, "tail -1 %s" % path)
        eq("%s ends with a PEM footer" % path, tail.strip(),
           "-----END CERTIFICATE-----")


def t_x509_subject_matches_the_filename_and_the_hash_link():
    s = sh()
    o, _ = run(s, "ls /etc/ssl/certs/*.pem | head -5")
    for path in o.split():
        base = path.rsplit("/", 1)[-1][:-4]
        subj, rc = run(s, "openssl x509 -noout -subject -in %s" % path)
        eq("x509 -subject rc for %s" % base, rc, 0)
        check("subject names the CA the filename does (%s)" % base,
              base.replace("_", " ") in subj, subj.strip()[:90])
        check("subject is ordered C, O, CN like a real root (%s)" % base,
              re.match(r"subject=C = \S+, O = .*, CN = ", subj),
              subj.strip()[:90])
        h, rc = run(s, "openssl x509 -noout -subject_hash -in %s" % path)
        eq("subject_hash rc for %s" % base, rc, 0)
        check("subject_hash is 8 hex", re.fullmatch(r"[0-9a-f]{8}", h.strip()),
              h.strip())
        # The hash link openssl computes must be the one on disk.
        o2, rc2 = run(s, "test -L /etc/ssl/certs/%s.0 && echo yes" % h.strip())
        eq("a %s.0 hash link exists for %s" % (h.strip(), base),
           (o2.strip(), rc2), ("yes", 0))
        tgt, _ = run(s, "readlink /etc/ssl/certs/%s.0" % h.strip())
        eq("and it points at this cert", tgt.strip(), "%s.pem" % base)
    o, rc = run(s, "openssl x509 -noout -dates -in "
                   "/etc/ssl/certs/ISRG_Root_X1.pem")
    eq("x509 -dates rc", rc, 0)
    check("notBefore present", "notBefore=" in o, o[:60])
    check("notAfter present", "notAfter=" in o, o[:60])
    o, rc = run(s, "openssl x509 -noout -subject -in /etc/hostname")
    eq("a non-certificate is rejected", rc, 1)
    check("with openssl's wording", "unable to load certificate" in o, o[:80])


def t_dpkg_and_the_filesystem_agree_about_the_ssl_packages():
    s = sh()
    for pkg in ("ca-certificates", "openssl"):
        o, _ = run(s, "for f in $(dpkg -L %s); do test -e $f || "
                      "echo MISSING $f; done" % pkg)
        eq("every file dpkg -L %s lists exists" % pkg, o.strip(), "")
    # /usr/sbin, not /usr/bin: that is where ca-certificates installs it and
    # where `command -v` finds it here. The old basename fallback in dpkg -S
    # answered for the wrong directory too, so this passed while asking
    # about a path that does not exist.
    for path in ("/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/openssl.cnf",
                 "/usr/bin/openssl", "/usr/sbin/update-ca-certificates"):
        o, rc = run(s, "dpkg -S %s" % path)
        eq("dpkg -S knows %s" % path, rc, 0)
        check("dpkg -S names a package for %s" % path, ": " in o, o[:70])


def t_the_payloads_random_string_path_works_end_to_end():
    """Exactly what the captured setup.sh does."""
    s = sh()
    o, rc = run(s, "command -v openssl")
    eq("command -v openssl succeeds", rc, 0)
    o, rc = run(s, "od -An -N2 -i /dev/urandom | tr -d ' '")
    eq("od on urandom rc", rc, 0)
    check("od gives a 16-bit number", o.strip().isdigit() and
          0 <= int(o.strip()) <= 65535, o.strip())
    o, rc = run(s, "expr $(od -An -N2 -i /dev/urandom 2>/dev/null | "
                   "tr -d ' ') % 32 + 4")
    check("the length expression is 4..35", o.strip().isdigit() and
          4 <= int(o.strip()) <= 35, o.strip())
    o, rc = run(s, "openssl rand -base64 256 | tr -dc 'A-Za-z0-9' | head -c 20")
    eq("the openssl branch produces 20 chars", len(o), 20)
    check("and they are alphanumeric", re.fullmatch(r"[A-Za-z0-9]{20}", o),
          repr(o))
    o, rc = run(s, "tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20")
    eq("the urandom fallback also produces 20 chars", len(o), 20)
    a, _ = run(s, "openssl rand -base64 32")
    b, _ = run(s, "openssl rand -base64 32")
    check("two rand calls differ", a != b, a[:20])
    a, _ = run(s, "od -An -N4 -tx1 /dev/urandom")
    b, _ = run(s, "od -An -N4 -tx1 /dev/urandom")
    check("two urandom reads differ", a != b, a.strip())
    o, _ = run(s, "echo $RANDOM $RANDOM")
    parts = o.split()
    check("$RANDOM gives two values in range",
          len(parts) == 2 and all(0 <= int(x) <= 32767 for x in parts), o)
    check("and they differ", len(set(parts)) == 2, o)


def t_openssl_passwd_and_ciphers():
    s = sh()
    o, rc = run(s, "openssl passwd -1 -salt xxxxxxxx password")
    eq("passwd -1 rc", rc, 0)
    check("passwd -1 shape", re.fullmatch(r"\$1\$xxxxxxxx\$[./A-Za-z0-9]{22}",
                                          o.strip()), o.strip())
    # md5crypt is computed, not shaped, so it must equal what a real
    # openssl produces. Both vectors below were taken from `openssl passwd`
    # on a machine with a real OpenSSL, not from this implementation.
    eq("passwd -1 matches real openssl", o.strip(),
       "$1$xxxxxxxx$UYCIxa628.9qXjpQCjM4a.")
    o4, _ = run(s, "openssl passwd -apr1 -salt abcdefgh pw")
    eq("passwd -apr1 matches real openssl", o4.strip(),
       "$apr1$abcdefgh$5VEbMkemELfbhC5ck.U.z1")
    o2, _ = run(s, "openssl passwd -1 -salt xxxxxxxx password")
    eq("passwd is deterministic for a fixed salt", o2, o)
    o3, _ = run(s, "openssl passwd -1 -salt yyyyyyyy password")
    check("a different salt gives a different hash", o3 != o, o3.strip())
    for flag, pref in (("-6", "$6$"), ("-5", "$5$"), ("-apr1", "$apr1$")):
        o, rc = run(s, "openssl passwd %s -salt abcdefgh pw" % flag)
        eq("passwd %s rc" % flag, rc, 0)
        check("passwd %s prefix" % flag, o.startswith(pref), o.strip()[:20])
    o, rc = run(s, "openssl ciphers")
    eq("ciphers rc", rc, 0)
    check("ciphers lists TLS 1.3 suites", "TLS_AES_256_GCM_SHA384" in o,
          o[:60])
    check("ciphers is colon separated", ":" in o, o[:60])


def t_xargs_stops_option_parsing_at_the_command():
    s = sh()
    o, rc = run(s, "echo /etc /nope | xargs -n1 -I{} sh -c "
                   "'test -e {} || echo MISSING {}'")
    eq("xargs -I with sh -c works", o.strip(), "MISSING /nope")
    o, _ = run(s, "echo a | xargs -I{} sh -c 'echo one; echo two'")
    eq("the whole script reaches sh", o.strip(), "one\ntwo")
    o, _ = run(s, "printf 'x\\ny\\n' | xargs -I% echo [%]")
    eq("plain -I still works", o.strip(), "[x]\n[y]")
    o, _ = run(s, "echo a b | xargs -n1 echo pre")
    eq("-n1 still works", o.strip(), "pre a\npre b")


def t_c_rehash_and_update_ca_certificates():
    s = sh()
    o, rc = run(s, "c_rehash")
    eq("c_rehash rc", rc, 0)
    check("c_rehash names the directory", "Doing /etc/ssl/certs" in o, o[:60])
    o, rc = run(s, "c_rehash /nonexistent-dir")
    eq("c_rehash on a missing directory fails", rc, 1)
    o, rc = run(s, "update-ca-certificates")
    eq("update-ca-certificates rc", rc, 0)
    check("it names the directory it updates",
          "Updating certificates in /etc/ssl/certs" in o, o[:80])
    check("and runs its hooks", "update.d" in o, o[:120])
    o, rc = run(s, "openssl rehash")
    eq("openssl rehash is the same command", rc, 0)


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
