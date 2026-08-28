#!/usr/bin/env python3
"""`sshd -T` against the config file, and against the handshake it describes.

An admin -- or an attacker deciding whether forwarding is available and
which keys will be accepted -- runs `sshd -T` to see what the daemon really
enforces. It is the one place the SSH server describes itself in full, so
it is the one place it can most easily contradict itself.

Measured on the guest (Debian 13.6, OpenSSH 10.0p2), which prints **103**
lines. We printed **44**, and 55 keys were missing outright, including
every one an attacker would actually read: ciphers, macs, kexalgorithms,
authorizedkeysfile, permitrootlogin's neighbours permitopen / permitlisten
/ forcecommand / disableforwarding, and permituserrc -- the switch behind
the ~/.ssh/rc execution path.

We also printed one key the real sshd does not have at all:

    x11maxdisplays 1000

Being *more* capable than the thing you imitate is a tell, the same shape
as hostnamectl accepting verbs the real one refuses (sweep 205).

The interesting half is not breadth but self-consistency. Copying the
guest's crypto lines verbatim would have been worse than omitting them: its
macs list offers umac-64 and umac-128, which this transport cannot perform,
so `sshd -T` would have advertised two algorithms the very next KEXINIT
disproved. The three lines a client can check against the handshake --
ciphers, macs, kexalgorithms -- are therefore rendered from
fakeshell.SSHD_ALGOS, which is now also where ssh_honeypot's transport
preferences come from. One definition, two readers.

What the transport really proposes, read off the wire:

    ciphers  chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,...
    macs     hmac-sha2-256-etm@openssh.com,...,hmac-sha1
    kex      mlkem768x25519-sha256,curve25519-sha256,...

Usage:  python3 sshdconftest.py
"""

import re
import sys

import fakeshell

CHECKS, FAILS = [], []


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want, "\n  -- " + note if note else ""))


def shell():
    return fakeshell.Shell(vfs=fakeshell.VFS(), peer="198.51.100.31",
                           peer_port=42111)


def run(sh, cmd):
    before = len(getattr(sh, "_err", []) or [])
    try:
        out = sh.run(cmd)
    except Exception as exc:                                   # noqa: BLE001
        return ("<raised %s: %s>" % (type(exc).__name__, exc), -1, "")
    err = "".join((getattr(sh, "_err", []) or [])[before:])
    return (out, getattr(sh, "last_rc", None), err)


# The guest's key order, measured. Repeats are real: sshd prints one line
# per value for the repeatable directives.
GUEST_KEYS = [
    "port", "addressfamily", "listenaddress", "listenaddress", "usepam",
    "pamservicename", "logingracetime", "x11displayoffset", "maxauthtries",
    "maxsessions", "clientaliveinterval", "clientalivecountmax",
    "requiredrsasize", "streamlocalbindmask", "unusedconnectiontimeout",
    "permitrootlogin", "ignorerhosts", "ignoreuserknownhosts",
    "hostbasedauthentication", "hostbasedusesnamefrompacketonly",
    "pubkeyauthentication", "kerberosauthentication", "kerberosorlocalpasswd",
    "kerberosticketcleanup", "gssapiauthentication", "gssapicleanupcredentials",
    "gssapikeyexchange", "gssapistrictacceptorcheck",
    "gssapistorecredentialsonrekey", "gssapikexalgorithms",
    "passwordauthentication", "kbdinteractiveauthentication", "printmotd",
    "printlastlog", "x11forwarding", "x11uselocalhost", "permittty",
    "permituserrc", "strictmodes", "tcpkeepalive", "permitemptypasswords",
    "compression", "gatewayports", "usedns", "allowtcpforwarding",
    "allowagentforwarding", "disableforwarding", "allowstreamlocalforwarding",
    "streamlocalbindunlink", "fingerprinthash", "exposeauthinfo",
    "refuseconnection", "debianbanner", "pidfile", "modulifile",
    "xauthlocation", "ciphers", "macs", "banner", "forcecommand",
    "chrootdirectory", "trustedusercakeys", "revokedkeys",
    "securitykeyprovider", "authorizedprincipalsfile", "versionaddendum",
    "authorizedkeyscommand", "authorizedkeyscommanduser",
    "authorizedprincipalscommand", "authorizedprincipalscommanduser",
    "hostkeyagent", "kexalgorithms", "casignaturealgorithms",
    "hostbasedacceptedalgorithms", "hostkeyalgorithms",
    "pubkeyacceptedalgorithms", "sshdsessionpath", "sshdauthpath",
    "persourcepenaltyexemptlist", "loglevel", "syslogfacility",
    "authorizedkeysfile", "hostkey", "hostkey", "hostkey", "acceptenv",
    "acceptenv", "acceptenv", "acceptenv", "authenticationmethods",
    "channeltimeout", "subsystem", "maxstartups", "persourcemaxstartups",
    "persourcenetblocksize", "permittunnel", "ipqos", "rekeylimit",
    "permitopen", "permitlisten", "permituserenvironment",
    "pubkeyauthoptions", "persourcepenalties",
]

sh = shell()
out, rc, _ = run(sh, "sshd -T")
lines = out.splitlines()
keys = [l.split(None, 1)[0] for l in lines if l.strip()]
vals = {}
for l in lines:
    p = l.split(None, 1)
    if len(p) == 2:
        vals.setdefault(p[0], []).append(p[1])
    elif p:
        vals.setdefault(p[0], []).append("")

check("sshd -T exits 0", rc, 0)
check("sshd -T prints as many lines as the real one", len(lines), 103,
      "the guest prints 103; we printed 44, so 55 keys an attacker reads "
      "were simply absent")
check("...in the real sshd's order", keys, GUEST_KEYS,
      "order is as comparable as content when diffing against a known host")

# ------------------------------------------- the key we should not have had
check("x11maxdisplays is not printed", "x11maxdisplays" in keys, False,
      "the real sshd has no such option; answering for it is being more "
      "capable than the thing we imitate")

# -------------------------------------------- nothing left unsubstituted
check("no placeholder survives into the output",
      [l for l in lines if "@@" in l], [],
      "the crypto lines are substituted at render time; a missed key would "
      "print the marker to the attacker")
check("every line has a value", [l for l in lines if len(l.split()) < 2], [],
      "sshd prints 'key value'; a bare key is not a shape it produces")

# ------------------------------ the three lines the handshake can disprove
algos = getattr(fakeshell, "SSHD_ALGOS_LIVE", None) \
    or getattr(fakeshell, "SSHD_ALGOS", None) or {}
for key, field in (("ciphers", "ciphers"), ("macs", "macs"),
                   ("kexalgorithms", "kexalgorithms")):
    want = ",".join(algos.get(field) or ())
    got = (vals.get(key) or [""])[0]
    check("sshd -T %s is what the transport offers" % key, got, want,
          "the dump and the KEXINIT are two readings of one question")

macs = (vals.get("macs") or [""])[0]
check("macs does not advertise umac", "umac" in macs, False,
      "the guest offers umac-64/umac-128 and this transport cannot; "
      "copying its line would have promised algorithms the next "
      "connection fails to negotiate. got %r" % macs[:90])
check("macs is not empty", bool(macs.strip()), True)

# ----------------------------------- the dump against the file on the box
body = (sh.fs.read("/etc/ssh/sshd_config") or b"").decode("latin-1")
declared = {}
for line in body.splitlines():
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    parts = line.split(None, 1)
    if len(parts) == 2:
        declared.setdefault(parts[0].lower(), parts[1].strip())

for directive in ("port", "permitrootlogin", "passwordauthentication",
                  "kbdinteractiveauthentication", "usepam", "x11forwarding",
                  "printmotd"):
    if directive not in declared:
        continue
    check("sshd -T agrees with sshd_config on %s" % directive,
          (vals.get(directive) or [""])[0], declared[directive],
          "one box, two ways of asking the same question")

check("the config file was readable at all", bool(declared), True,
      "if this fails the comparisons above proved nothing")

# --------------------------------- repeatable directives repeat correctly
for key, want in (("hostkey", 3), ("acceptenv", 4), ("listenaddress", 2)):
    check("%s is printed %d times" % (key, want),
          len(vals.get(key) or []), want,
          "sshd prints one line per value; folding them into one line, or "
          "letting a single override overwrite all of them, is visible")
check("the three hostkey lines are distinct",
      len(set(vals.get("hostkey") or [])), 3,
      "an override lookup applied to a repeatable key made all three the "
      "same path")

# ------------------------------------------ the port reaches listenaddress
ports = {l.rsplit(":", 1)[-1] for l in (vals.get("listenaddress") or [])}
check("listenaddress carries the configured port", ports, {"22"},
      "sshd_config says Port 22, so both listenaddress lines must say 22 "
      "-- the guest's say 2222 because its sshd really is on 2222")

# ------------------------------------- keys an attacker specifically reads
for key, want in (("permituserrc", "yes"),
                  ("authorizedkeysfile",
                   ".ssh/authorized_keys .ssh/authorized_keys2"),
                  ("permitopen", "any"), ("forcecommand", "none"),
                  ("disableforwarding", "no"), ("chrootdirectory", "none"),
                  ("pidfile", "/run/sshd.pid"),
                  ("sshdsessionpath", "/usr/lib/openssh/sshd-session")):
    check("%s is reported" % key, (vals.get(key) or ["<missing>"])[0], want)

# ------------------------------------------------- the definition is shared
base = getattr(fakeshell, "SSHD_ALGOS", None)
check("fakeshell defines the algorithm source", isinstance(base, dict), True,
      "ssh_honeypot builds its transport preferences from this; if it is "
      "gone the two can drift again")
if isinstance(base, dict):
    check("...with the three negotiable families",
          sorted(base), ["ciphers", "kexalgorithms", "macs"])
    check("...and none of them empty",
          [k for k, v in base.items() if not v], [])

for f in FAILS:
    print(" ", f)
print("   sshdconf: %d checks, %d differ" % (len(CHECKS), len(FAILS)))
sys.exit(1 if FAILS else 0)
