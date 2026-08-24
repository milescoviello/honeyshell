#!/usr/bin/env python3
"""Does the box agree with itself about who it is?

Hostname, FQDN, machine ID, boot ID and address are the first things a bot
reports home, and each of them had more than one answer.

  - `hostnamectl` printed Machine ID 4f2a9c1e8b7d4a3f9e6c2b8a1d5f7e30 while
    /etc/machine-id said 4f2a9c1b7e3d48a6b5c0d9e8f7a61234, and Boot ID
    a1b2c3d4e5f6470891a2b3c4d5e6f708 -- a hand-typed a1b2c3... -- while
    /proc/sys/kernel/random/boot_id said a different UUID. hostnamectl reads
    exactly those two files, so it could not have disagreed with either.
  - `hostname -d` printed the short hostname, which is the one thing a
    domain is not. `hostname -A` printed the short hostname where the FQDN
    list goes. `hostname -i` printed the hostname where an IP goes, while
    getent had 127.0.1.1 from /etc/hosts all along.
  - `dnsdomainname` and `domainname` were unimplemented, so they answered
    "missing operand"; `nisdomainname` and `ypdomainname` said command not
    found, though dpkg says the hostname package that ships all four is
    installed.
  - `hostname newname` was a silent no-op -- the one command whose entire
    job is to change that answer -- and `hostnamectl set-hostname` likewise.
  - `hostnamectl --static` printed the whole status block instead of the one
    value a script reads.
  - `ip -4 addr` printed the inet6 lines and `ip -6 addr` printed the inet
    lines; `ip addr show eth0` listed lo as well. The selector flags parsed
    and were then dropped.
  - `ping web01` printed "PING web01 (web01)", putting a name where the
    resolved address belongs.
  - `logger hello` appended nothing, so its only observable effect did not
    happen and `tail /var/log/syslog` disagreed that anything had.

Run from `honeypot/`, or on the guest.
"""

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


def t_every_view_of_the_hostname_agrees():
    """The question a bot asks first."""
    s = sh()
    answers = {}
    for cmd in ("hostname", "hostname -s", "uname -n",
                "cat /etc/hostname", "cat /proc/sys/kernel/hostname",
                "hostnamectl --static", "hostnamectl hostname",
                "uname -a | awk '{print $2}'", "echo $HOSTNAME"):
        o, rc = run(s, cmd)
        eq("%s succeeds" % cmd, rc, 0)
        answers[cmd] = o.strip()
    eq("all nine agree", len(set(answers.values())), 1)
    if len(set(answers.values())) != 1:
        for k, v in answers.items():
            print("      %-40s %r" % (k, v))


def t_machine_id_has_one_value():
    """The contradiction this sweep started from."""
    s = sh()
    vals = {}
    for cmd in ("cat /etc/machine-id", "cat /var/lib/dbus/machine-id",
                "hostnamectl | awk '/Machine ID/ {print $3}'"):
        o, rc = run(s, cmd)
        eq("%s succeeds" % cmd, rc, 0)
        vals[cmd] = o.strip()
    eq("machine id is one value", len(set(vals.values())), 1)
    if len(set(vals.values())) != 1:
        for k, v in vals.items():
            print("      %-46s %r" % (k, v))
    v = list(vals.values())[0]
    check("machine id is 32 lowercase hex", re.fullmatch(r"[0-9a-f]{32}", v), v)


def t_boot_id_has_one_value_and_is_a_uuid():
    s = sh()
    o, rc = run(s, "cat /proc/sys/kernel/random/boot_id")
    eq("boot_id readable", rc, 0)
    raw = o.strip()
    check("boot_id is a dashed uuid",
          re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                       r"[0-9a-f]{4}-[0-9a-f]{12}", raw), raw)
    o2, _ = run(s, "hostnamectl | awk '/Boot ID/ {print $3}'")
    eq("hostnamectl boot id is the same uuid without dashes",
       o2.strip(), raw.replace("-", ""))
    o3, _ = run(s, "journalctl --list-boots")
    check("journalctl --list-boots uses it too", raw.replace("-", "") in o3,
          o3[:80])
    # It is fixed for the life of the boot: reading twice must not change it.
    o4, _ = run(s, "cat /proc/sys/kernel/random/boot_id")
    eq("boot_id is stable across reads", o4.strip(), raw)
    # /proc/sys/kernel/random/uuid is the one that must differ each read.
    a, _ = run(s, "cat /proc/sys/kernel/random/uuid")
    b, _ = run(s, "cat /proc/sys/kernel/random/uuid")
    check("random/uuid does change per read", a.strip() != b.strip(),
          "%r twice" % a.strip())


def t_boot_id_is_not_the_esp_filesystem_uuid():
    """Two different things were briefly called BOOT_UUID."""
    s = sh()
    bid, _ = run(s, "cat /proc/sys/kernel/random/boot_id")
    esp, _ = run(s, "blkid /dev/sda15")
    m = re.search(r'\bUUID="([^"]+)"', esp)
    check("the ESP still has its own short vfat UUID", m, esp[:80])
    if m:
        check("boot id and ESP UUID are different values",
              bid.strip() != m.group(1), bid.strip())
        check("ESP UUID keeps the vfat 8-char form",
              re.fullmatch(r"[0-9A-F]{4}-[0-9A-F]{4}", m.group(1)),
              m.group(1))
        o, _ = run(s, "readlink -f /dev/disk/by-uuid/%s" % m.group(1))
        eq("and by-uuid still resolves it", o.strip(), "/dev/sda15")


def t_fqdn_domain_and_address_come_from_hosts():
    s = sh()
    hosts, _ = run(s, "cat /etc/hosts")
    short, _ = run(s, "hostname")
    short = short.strip()
    fq, rc = run(s, "hostname -f")
    eq("hostname -f succeeds", rc, 0)
    fq = fq.strip()
    check("the FQDN appears in /etc/hosts", fq in hosts, hosts[:120])
    check("the FQDN starts with the short name", fq.split(".")[0] == short,
          "%r vs %r" % (fq, short))
    d, rc = run(s, "hostname -d")
    eq("hostname -d is the domain part", d.strip(), fq.split(".", 1)[1])
    dd, rc = run(s, "dnsdomainname")
    eq("dnsdomainname matches hostname -d", dd.strip(), d.strip())
    a, rc = run(s, "hostname -A")
    check("hostname -A lists the FQDN", fq in a, repr(a))
    check("hostname -A is not just the short name", a.strip() != short, a)
    i, rc = run(s, "hostname -i")
    eq("hostname -i succeeds", rc, 0)
    check("hostname -i is an IP address",
          re.fullmatch(r"[0-9]{1,3}(\.[0-9]{1,3}){3}", i.strip()), i.strip())
    ge, _ = run(s, "getent hosts %s" % short)
    check("and it is the address getent gives", i.strip() in ge, ge[:80])


def t_hostname_i_and_I_are_different_questions():
    s = sh()
    i, _ = run(s, "hostname -i")
    ii, _ = run(s, "hostname -I")
    check("-i is the hosts-file address", i.strip().startswith("127."),
          i.strip())
    check("-I is the interface address", not ii.strip().startswith("127."),
          ii.strip())
    ipa, _ = run(s, "ip -4 addr show %s" % fs.IFACE)
    check("-I matches what ip addr shows", ii.strip() in ipa, ipa[:120])


def t_nis_domain_tools_all_exist_and_agree():
    s = sh()
    outs = {}
    for cmd in ("domainname", "nisdomainname", "ypdomainname"):
        o, rc = run(s, cmd)
        eq("%s runs" % cmd, rc, 0)
        outs[cmd] = o.strip()
    eq("all three give the same NIS domain", len(set(outs.values())), 1)
    eq("which is unset", list(outs.values())[0], "(none)")
    o, rc = run(s, "hostname -y")
    eq("hostname -y agrees it is unset", rc, 1)
    check("hostname -y message", "Local domain name not set" in o, o[:60])
    for cmd in ("dnsdomainname", "domainname", "nisdomainname",
                "ypdomainname", "hostname"):
        o, rc = run(s, "command -v %s" % cmd)
        eq("%s is on PATH" % cmd, rc, 0)


def t_changing_the_hostname_changes_every_view():
    s = sh()
    o, rc = run(s, "hostname webtwo")
    eq("hostname <name> succeeds for root", (o, rc), ("", 0))
    for cmd in ("hostname", "uname -n", "cat /proc/sys/kernel/hostname"):
        o, _ = run(s, cmd)
        eq("after rename, %s" % cmd, o.strip(), "webtwo")
    # hostname(1) does not write /etc/hostname; hostnamectl does.
    o, _ = run(s, "cat /etc/hostname")
    eq("hostname(1) leaves /etc/hostname alone", o.strip(), "web01")
    # ...so the *static* name has not changed, only the transient one.
    # This check used to expect "webtwo" two lines above the check that
    # /etc/hostname still says web01 -- two expectations that cannot both
    # be true, because --static is the file. Measured on the guest:
    # `hostname tempname` leaves `hostnamectl --static` reading web01.
    o, _ = run(s, "hostnamectl --static")
    eq("after rename, hostnamectl --static is still the file", o.strip(),
       "web01")
    o, _ = run(s, "hostnamectl --transient")
    eq("after rename, hostnamectl --transient is the new name", o.strip(),
       "webtwo")
    o, _ = run(s, "hostnamectl")
    check("the status block names both", "Transient hostname: webtwo" in o,
          o[:80])
    # The new name is not in /etc/hosts, so the resolver cannot make an FQDN.
    o, rc = run(s, "hostname -f")
    eq("hostname -f now fails like the resolver does", rc, 1)
    check("with the resolver's message", "Name or service not known" in o,
          o[:60])
    s2 = sh()
    o, rc = run(s2, "hostnamectl set-hostname webthree")
    eq("hostnamectl set-hostname succeeds", (o, rc), ("", 0))
    for cmd in ("hostname", "uname -n", "cat /etc/hostname",
                "hostnamectl --static", "cat /proc/sys/kernel/hostname"):
        o, _ = run(s2, cmd)
        eq("after hostnamectl set-hostname, %s" % cmd, o.strip(), "webthree")


def t_a_non_root_user_cannot_rename_the_box():
    s = fs.Shell(fs.VFS(), peer="203.0.113.77", user="www-data")
    s.exec_mode = True
    o, rc = run(s, "hostname nope")
    eq("non-root rename rc", rc, 1)
    check("non-root rename message", "must be root" in o, o[:70])
    o, _ = run(s, "hostname")
    eq("and the name is unchanged", o.strip(), "web01")


def t_hostnamectl_single_value_options():
    s = sh()
    for opt in ("--static", "--transient"):
        o, rc = run(s, "hostnamectl %s" % opt)
        eq("hostnamectl %s rc" % opt, rc, 0)
        eq("hostnamectl %s prints one line" % opt,
           len(o.strip().splitlines()), 1)
        check("hostnamectl %s prints no labels" % opt, ":" not in o, o[:60])
    o, _ = run(s, "hostnamectl")
    eq("bare hostnamectl still prints the block",
       len(o.strip().splitlines()) > 5, True)


def t_hostnamectl_hardware_matches_dmi():
    s = sh()
    o, _ = run(s, "hostnamectl")
    d = dict((k.strip(), v.strip())
             for k, v in (l.split(":", 1) for l in o.splitlines() if ":" in l))
    for label, path in (("Hardware Vendor", "/sys/class/dmi/id/sys_vendor"),
                        ("Hardware Model", "/sys/class/dmi/id/product_name"),
                        ("Firmware Version", "/sys/class/dmi/id/bios_version")):
        want, rc = run(s, "cat %s" % path)
        eq("%s matches %s" % (label, path), d.get(label), want.strip())
    o2, _ = run(s, "systemd-detect-virt")
    eq("Virtualization matches systemd-detect-virt", d.get("Virtualization"),
       o2.strip())
    o3, _ = run(s, "uname -r")
    check("Kernel line matches uname -r", d.get("Kernel", "").endswith(o3.strip()),
          d.get("Kernel"))


def t_ip_family_and_device_selectors_filter():
    s = sh()
    o, _ = run(s, "ip -4 addr")
    eq("ip -4 addr has no inet6 lines", "inet6" in o, False)
    check("ip -4 addr still has inet lines", "inet " in o, o[:80])
    o, _ = run(s, "ip -6 addr")
    check("ip -6 addr has inet6 lines", "inet6" in o, o[:80])
    eq("ip -6 addr has no inet lines", bool(re.search(r"^\s+inet ", o, re.M)),
       False)
    for form in ("ip addr show %s", "ip a s %s", "ip addr show dev %s"):
        o, rc = run(s, form % fs.IFACE)
        eq((form % fs.IFACE) + " rc", rc, 0)
        eq("%s lists one interface" % (form % fs.IFACE),
           len(re.findall(r"^\d+: ", o, re.M)), 1)
        check("%s lists the right one" % (form % fs.IFACE),
              fs.IFACE in o and " lo:" not in o, o[:80])
    o, rc = run(s, "ip addr show wlan0")
    eq("an absent device is an error", rc, 1)
    check("with iproute2's wording", 'does not exist' in o, o[:70])
    o, _ = run(s, "ip addr")
    eq("bare ip addr still lists both", len(re.findall(r"^\d+: ", o, re.M)), 2)
    o, _ = run(s, "ip -6 route")
    check("ip -6 route is v6 only", "default via" not in o, o[:80])


def t_ping_prints_the_resolved_address():
    s = sh()
    o, _ = run(s, "ping -c1 web01")
    m = re.match(r"PING (\S+) \(([^)]+)\)", o)
    check("ping prints a PING line", m, o[:60])
    if m:
        check("the parenthesised field is an address, not the name",
              re.fullmatch(r"[0-9]{1,3}(\.[0-9]{1,3}){3}", m.group(2)),
              m.group(2))
        ge, _ = run(s, "getent hosts web01")
        check("and it is what getent resolves", m.group(2) in ge, ge[:60])
    o, rc = run(s, "ping -c1 192.0.2.9")
    check("a literal address is used as-is", "(192.0.2.9)" in o, o[:60])
    o, rc = run(s, "ping -c1 nosuchhostname")
    eq("an unresolvable short name fails in the resolver", rc, 2)
    check("with ping's wording", "Name or service not known" in o, o[:70])


def t_logger_writes_the_line_it_claims_to():
    s = sh()
    before, _ = run(s, "wc -l < /var/log/syslog")
    o, rc = run(s, "logger -t sweeptag hello world")
    eq("logger rc", (o, rc), ("", 0))
    after, _ = run(s, "tail -1 /var/log/syslog")
    check("the line is there", "sweeptag: hello world" in after, after[:90])
    host, _ = run(s, "hostname")
    check("tagged with the current hostname", host.strip() in after,
          after[:90])
    n1, n2 = int(before.strip()), int(run(s, "wc -l < /var/log/syslog")[0])
    eq("syslog grew by exactly one line", n2 - n1, 1)
    run(s, "echo from-a-pipe | logger -t pipetag")
    o, _ = run(s, "tail -1 /var/log/syslog")
    check("logger reads stdin too", "pipetag: from-a-pipe" in o, o[:90])
    # The timestamp has to look like the lines already in the file.
    o, _ = run(s, "tail -2 /var/log/syslog")
    for line in o.splitlines():
        check("syslog line shape", re.match(r"^[A-Z][a-z]{2} [ 0-9]\d "
                                            r"\d\d:\d\d:\d\d \S+ ", line),
              repr(line[:50]))


def t_hosts_file_is_well_formed():
    s = sh()
    o, _ = run(s, "cat /etc/hosts")
    check("localhost is 127.0.0.1", re.search(r"^127\.0\.0\.1\s+localhost",
                                              o, re.M), o[:80])
    check("the box has a 127.0.1.1 entry, Debian style",
          re.search(r"^127\.0\.1\.1\s+\S+\.\S+\s+\S+", o, re.M), o[:120])
    check("ip6-localhost is present", "ip6-localhost" in o, o[:120])
    for name in ("localhost", "web01"):
        o2, rc = run(s, "getent hosts %s" % name)
        eq("getent resolves %s" % name, rc, 0)


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
