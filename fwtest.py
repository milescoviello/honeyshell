r"""The firewall accepted every change and kept none of them.

Sixtieth coherence sweep. Turning the firewall off, or shutting rivals
out with it, is standard kit behaviour -- `iptables -F; iptables -P INPUT
DROP` sits in the middle of most miner installers. Nothing here had asked
whether that works.

Nothing was stored at all. -A, -I, -D, -P, -N, -X and -F each returned 0
and changed nothing, so the box always showed three empty ACCEPT chains
however many rules had just been added. `iptables -P INPUT DROP` reported
success and left the policy at ACCEPT, so a script that sets a rule and
reads it back to confirm got the wrong answer twice over.

Around that:

  - `iptables -L INPUT` printed all three chains, so asking about one
    chain answered about the whole table.
  - iptables-save was not implemented and fell through to the generic
    unimplemented-binary handler, answering "iptables-save: missing
    operand" -- it takes no operand -- while `iptables -S` answered the
    same question correctly.
  - An unrecognised option returned 0. Real iptables prints
    `unknown option "--x"` and exits 2.
  - ip6tables was an alias for the same function and shared one table, so
    a v6 rule appeared in the v4 listing.
  - `iptables --version` said 1.8.9 while dpkg on the same box reported
    1.8.11-2. The version string is repeated in every iptables error
    message, so the two disagreed in the most quotable place there is.

Reference measured against real iptables (nf_tables) on the dev host for
the message shapes; the version is this box's own dpkg entry.

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


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


# -- the version everything quotes ---------------------------------------

def t_version_matches_dpkg():
    s = shell()
    v = out(s, "iptables --version")
    check("nf_tables backend", v.endswith("(nf_tables)"), v)
    pkg = out(s, "dpkg -l iptables | tail -1 | awk '{print $3}'")
    check("version matches dpkg", pkg.split("-")[0] in v,
          "iptables says %r, dpkg says %r" % (v, pkg))
    check("ip6tables agrees", pkg.split("-")[0] in out(s, "ip6tables --version"),
          out(s, "ip6tables --version"))
    check("iptables-save agrees",
          pkg.split("-")[0] in out(s, "iptables-save --version"),
          out(s, "iptables-save --version"))


# -- empty state ---------------------------------------------------------

def t_a_clean_box_has_three_accept_chains():
    s = shell()
    eq("-S", out(s, "iptables -S"),
       "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT")
    body = out(s, "iptables -L")
    for c in ("INPUT", "FORWARD", "OUTPUT"):
        check("-L names %s" % c, "Chain %s (policy ACCEPT)" % c in body, body)


# -- rules stick ---------------------------------------------------------

def t_an_appended_rule_is_there_afterwards():
    s = shell()
    eq("append is silent", out(s, "iptables -A INPUT -p tcp --dport 8080 -j ACCEPT"), "")
    # iptables writes the spec back in its own canonical form: a port
    # match implies `-m tcp`, and a bare address gains its /32. Measured
    # on the guest, where `-A INPUT -p tcp --dport 2222 -j ACCEPT` comes
    # back as `-A INPUT -p tcp -m tcp --dport 2222 -j ACCEPT`. This check
    # asserted the spec verbatim, which is what we used to echo.
    check("-S has it",
          "-A INPUT -p tcp -m tcp --dport 8080 -j ACCEPT"
          in out(s, "iptables -S"), out(s, "iptables -S"))
    check("-L has it", "ACCEPT" in out(s, "iptables -L INPUT"),
          out(s, "iptables -L INPUT"))


def t_insert_goes_first():
    s = shell()
    out(s, "iptables -A INPUT -p tcp -j ACCEPT")
    out(s, "iptables -I INPUT -s 1.2.3.4 -j DROP")
    rules = [l for l in out(s, "iptables -S INPUT").splitlines()
             if l.startswith("-A")]
    check("two rules", len(rules) == 2, str(rules))
    check("insert is first", "1.2.3.4" in rules[0], str(rules))


def t_delete_removes_exactly_that_rule():
    s = shell()
    out(s, "iptables -A INPUT -p tcp -j ACCEPT")
    out(s, "iptables -A INPUT -s 1.2.3.4 -j DROP")
    out(s, "iptables -D INPUT -s 1.2.3.4 -j DROP")
    body = out(s, "iptables -S INPUT")
    check("the other survives", "-p tcp -j ACCEPT" in body, body)
    check("the deleted one is gone", "1.2.3.4" not in body, body)


def t_deleting_a_rule_that_is_not_there():
    s = shell()
    o = out(s, "iptables -D INPUT -s 9.9.9.9 -j DROP")
    check("reports it", "does a matching rule exist" in o, o)


# -- policy --------------------------------------------------------------

def t_the_policy_change_a_kit_makes():
    s = shell()
    eq("silent", out(s, "iptables -P INPUT DROP"), "")
    check("-S shows DROP", "-P INPUT DROP" in out(s, "iptables -S"),
          out(s, "iptables -S"))
    check("-L shows DROP", "policy DROP" in out(s, "iptables -L INPUT"),
          out(s, "iptables -L INPUT"))
    check("only INPUT changed", "-P OUTPUT ACCEPT" in out(s, "iptables -S"),
          out(s, "iptables -S"))


def t_a_bad_policy_is_refused():
    s = shell()
    o = out(s, "iptables -P INPUT BANANA")
    check("refused", "Bad policy name" in o, o)
    check("unchanged", "-P INPUT ACCEPT" in out(s, "iptables -S"),
          out(s, "iptables -S"))


def t_policy_on_a_user_chain_is_refused():
    s = shell()
    out(s, "iptables -N mychain")
    o = out(s, "iptables -P mychain DROP")
    check("refused", "Bad built-in chain name" in o, o)


# -- chains --------------------------------------------------------------

def t_new_and_delete_chain():
    s = shell()
    out(s, "iptables -N minerchain")
    check("-S lists it", "-N minerchain" in out(s, "iptables -S"),
          out(s, "iptables -S"))
    check("-L lists it", "Chain minerchain" in out(s, "iptables -L"),
          out(s, "iptables -L"))
    out(s, "iptables -X minerchain")
    check("gone", "minerchain" not in out(s, "iptables -S"),
          out(s, "iptables -S"))


def t_a_builtin_chain_cannot_be_deleted():
    s = shell()
    o = out(s, "iptables -X INPUT")
    check("refused", "Can't delete built-in chain" in o, o)
    check("still there", "-P INPUT ACCEPT" in out(s, "iptables -S"), "")


def t_duplicate_chain():
    s = shell()
    out(s, "iptables -N dup")
    o = out(s, "iptables -N dup")
    check("reports it", "already exists" in o, o)


# -- flush ---------------------------------------------------------------

def t_flush_clears_rules_but_not_policy():
    s = shell()
    out(s, "iptables -A INPUT -p tcp -j ACCEPT")
    out(s, "iptables -P INPUT DROP")
    out(s, "iptables -F")
    body = out(s, "iptables -S")
    check("rules gone", "-A INPUT" not in body, body)
    check("policy kept", "-P INPUT DROP" in body, body)


def t_flush_one_chain_only():
    s = shell()
    out(s, "iptables -A INPUT -p tcp -j ACCEPT")
    out(s, "iptables -A OUTPUT -p udp -j ACCEPT")
    out(s, "iptables -F INPUT")
    body = out(s, "iptables -S")
    check("INPUT flushed", "-A INPUT" not in body, body)
    check("OUTPUT kept", "-A OUTPUT" in body, body)


def t_the_kit_one_liner():
    """iptables -F; -X; -P ACCEPT x3 -- open the box right up."""
    s = shell()
    out(s, "iptables -A INPUT -p tcp -j DROP; iptables -P INPUT DROP; "
           "iptables -N tmpchain")
    out(s, "iptables -F; iptables -X; iptables -P INPUT ACCEPT; "
           "iptables -P FORWARD ACCEPT; iptables -P OUTPUT ACCEPT")
    eq("back to a clean table", out(s, "iptables -S"),
       "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT")


# -- scoping -------------------------------------------------------------

def t_listing_one_chain_lists_one_chain():
    s = shell()
    eq("one Chain header", out(s, "iptables -L INPUT | grep -c '^Chain'"), "1")
    eq("and it is INPUT", out(s, "iptables -L INPUT | head -1"),
       "Chain INPUT (policy ACCEPT)")
    eq("-S too", out(s, "iptables -S INPUT | grep -c '^-P'"), "1")


def t_listing_everything_lists_everything():
    s = shell()
    eq("three chains", out(s, "iptables -L | grep -c '^Chain'"), "3")


# -- iptables-save --------------------------------------------------------

def t_iptables_save_dumps_the_ruleset():
    s = shell()
    out(s, "iptables -A INPUT -p tcp --dport 22 -j ACCEPT")
    body = out(s, "iptables-save")
    check("no missing operand", "missing operand" not in body, body[:80])
    check("has the header", body.startswith("# Generated by iptables-save"),
          body[:60])
    check("declares the table", "*filter" in body, body[:80])
    check("has the chains", ":INPUT ACCEPT [0:0]" in body, body[:120])
    check("has the rule",
          "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT" in body, body[:200])
    check("commits", "COMMIT" in body, body[-80:])


def t_save_and_dash_s_agree():
    s = shell()
    out(s, "iptables -A INPUT -p tcp -j ACCEPT; iptables -P OUTPUT DROP")
    saved = [l for l in out(s, "iptables-save").splitlines()
             if l.startswith("-A")]
    listed = [l for l in out(s, "iptables -S").splitlines()
              if l.startswith("-A")]
    eq("same rules", saved, listed)
    check("save shows the policy", ":OUTPUT DROP" in out(s, "iptables-save"),
          out(s, "iptables-save"))


# -- errors --------------------------------------------------------------

def t_an_unknown_option_is_an_error():
    s = shell()
    o = out(s, "iptables --frobnicate")
    check("names the option", 'unknown option "--frobnicate"' in o, o)
    check("suggests help", "Try `iptables -h'" in o, o)
    _o, rc = s.run("iptables --frobnicate"), s.last_rc
    s._err.clear()
    eq("rc 2", rc, 2)


def t_rule_spec_options_are_not_rejected():
    """The rule vocabulary is open-ended; only pre-verb options are checked."""
    s = shell()
    for rule in ("-A INPUT -p tcp --dport 80 -j ACCEPT",
                 "-A INPUT -m state --state NEW -j ACCEPT",
                 "-A INPUT -s 10.0.0.0/8 -d 0.0.0.0/0 -i eth0 -j DROP",
                 "-A OUTPUT -p udp -m multiport --dports 53,123 -j ACCEPT"):
        o = out(s, "iptables %s" % rule)
        check("accepted: %s" % rule[:38], "unknown option" not in o, o)


# -- the two families are separate ---------------------------------------

def t_ip6tables_has_its_own_table():
    s = shell()
    out(s, "ip6tables -A INPUT -j DROP")
    check("v6 has the rule", "-A INPUT -j DROP" in out(s, "ip6tables -S"),
          out(s, "ip6tables -S"))
    check("v4 does not", "-A INPUT" not in out(s, "iptables -S"),
          out(s, "iptables -S"))
    out(s, "iptables -P INPUT DROP")
    check("v6 policy untouched", "-P INPUT ACCEPT" in out(s, "ip6tables -S"),
          out(s, "ip6tables -S"))


TESTS = [t_version_matches_dpkg, t_a_clean_box_has_three_accept_chains,
         t_an_appended_rule_is_there_afterwards, t_insert_goes_first,
         t_delete_removes_exactly_that_rule,
         t_deleting_a_rule_that_is_not_there, t_the_policy_change_a_kit_makes,
         t_a_bad_policy_is_refused, t_policy_on_a_user_chain_is_refused,
         t_new_and_delete_chain, t_a_builtin_chain_cannot_be_deleted,
         t_duplicate_chain, t_flush_clears_rules_but_not_policy,
         t_flush_one_chain_only, t_the_kit_one_liner,
         t_listing_one_chain_lists_one_chain,
         t_listing_everything_lists_everything,
         t_iptables_save_dumps_the_ruleset, t_save_and_dash_s_agree,
         t_an_unknown_option_is_an_error, t_rule_spec_options_are_not_rejected,
         t_ip6tables_has_its_own_table]


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
