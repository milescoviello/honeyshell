#!/usr/bin/env python3
"""Does any command still mistake an option's value for its operand?

Four sweeps in a row found the same bug in different commands, so this one
went looking for the whole family at once instead of a fifth instance.

The shape: a command collects its operands by taking the first token that
does not begin with a dash. That token is the *argument* of whatever flag
came before it, so the command works on the wrong thing and says so
convincingly:

    ssh -o StrictHostKeyChecking=no root@10.0.0.5 id
        -> ssh: connect to host StrictHostKeyChecking=no port 22
    ping -c 2 10.0.0.5     -> ping: 2: Name or service not known
    od   -N 4 file         -> od: 4: No such file or directory
    nl   -s : file         -> nl: :: No such file or directory
    gzip -S .z file        -> gzip: .z: No such file or directory

The detector is the useful part and it is what this suite runs: give the
command a nonexistent operand, and check the error still names *that
operand* once a value-taking flag is put in front of it. It found sixteen
combinations across seven commands in one pass, all from a single shared
helper that treated any non-dash token as a file.

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                        # noqa: E402

PASS, FAIL = [], []
MISSING = "/nonexistent-zz"

# (command, a value-taking flag with its value)
COMBOS = [
    ("od", "-N 4"), ("od", "-j 1"), ("od", "-w 8"), ("od", "-A d"),
    ("od", "-t x1"), ("shuf", "-n 1"), ("shuf", "-i 1-3"),
    ("base32", "-w 0"), ("base64", "-w 0"),
    ("nl", "-w 2"), ("nl", "-b a"), ("nl", "-s :"),
    ("expand", "-t 4"), ("unexpand", "-t 4"),
    ("fmt", "-w 40"), ("pr", "-w 60"), ("pr", "-l 20"),
    ("gzip", "-S .z"), ("tac", "-s ,"), ("hexdump", "-n 4"),
    ("head", "-n 1"), ("tail", "-n 1"), ("cut", "-d :"), ("sort", "-k 1"),
    ("grep", "-m 1 pat"), ("du", "-d 1"), ("stat", "-c %n"),
    ("split", "-b 10"), ("fold", "-w 10"), ("paste", "-d ,"),
]


def sh():
    s = fs.Shell(fs.VFS(), peer="203.0.113.77")
    s.exec_mode = True
    return s


def run(s, cmd):
    out = s.run(cmd)
    err = "".join(s._err)
    s._err.clear()
    return out + err


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-52s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


def t_the_operand_survives_a_value_taking_flag():
    """The detector, as an invariant."""
    s = sh()
    for cmd, opt in COMBOS:
        plain = run(s, "%s %s 2>&1" % (cmd, MISSING))
        if MISSING not in plain:
            # This command does not name its operand even without a flag,
            # so it cannot tell us anything. Skip rather than pretend.
            continue
        withopt = run(s, "%s %s %s 2>&1" % (cmd, opt, MISSING))
        check("%s %s still names its operand" % (cmd, opt),
              MISSING in withopt, withopt[:70])


def t_the_values_actually_take_effect():
    """Consuming the argument is only half of it: the option has to do
    something, or the fix would be to swallow it and carry on."""
    s = sh()
    run(s, "printf 'aaa\\nbbb\\nccc\\nddd\\n' > /tmp/o.txt")
    out = run(s, "od -N 4 -c /tmp/o.txt")
    check("od -N limits the dump", out.strip().endswith("0000004"),
          out[-40:])
    eq("shuf -n limits the lines",
       run(s, "shuf -n 1 /tmp/o.txt | wc -l").strip(), "1")
    eq("shuf -n attached form",
       run(s, "shuf -n1 /tmp/o.txt | wc -l").strip(), "1")
    eq("shuf without -n returns all",
       run(s, "shuf /tmp/o.txt | wc -l").strip(), "4")
    check("nl -s changes the separator",
          run(s, "nl -s : /tmp/o.txt | head -1").startswith("     1:aaa"),
          run(s, "nl -s : /tmp/o.txt | head -1")[:20])
    run(s, "printf abc > /tmp/g.txt")
    run(s, "gzip -S .z -k /tmp/g.txt")
    check("gzip -S names the output",
          "/tmp/g.txt.z" in run(s, "ls /tmp/g.txt*"),
          run(s, "ls /tmp/g.txt*")[:60])


def t_ssh_and_ping_stay_fixed():
    """The two the family was first found in."""
    s = sh()
    out = run(s, "ssh -o StrictHostKeyChecking=no -p 2222 root@10.0.0.5 id")
    check("ssh keeps its host", "host 10.0.0.5 port 2222" in out, out[:70])
    out = run(s, "ping -c 2 10.0.0.5")
    check("ping -c 2 keeps its host", "2 packets transmitted" in out,
          out[-60:])
    out = run(s, "ping -c1 10.0.0.5")
    check("ping -c1 sends one", "1 packets transmitted" in out, out[-60:])


def t_flagless_use_is_unchanged():
    """The parser must not start eating operands that were never options."""
    s = sh()
    run(s, "printf 'x\\ny\\n' > /tmp/p.txt")
    eq("nl", run(s, "nl /tmp/p.txt | wc -l").strip(), "2")
    eq("od", run(s, "od -c /tmp/p.txt | head -1").strip().startswith(
        "0000000"), True)
    eq("base64", run(s, "base64 /tmp/p.txt").strip(), "eAp5Cg==")
    eq("shuf", run(s, "shuf /tmp/p.txt | wc -l").strip(), "2")
    run(s, "printf abc > /tmp/q.txt; gzip -k /tmp/q.txt")
    check("gzip default suffix", "/tmp/q.txt.gz" in run(s, "ls /tmp/q.txt*"),
          run(s, "ls /tmp/q.txt*")[:50])


def t_a_value_must_not_become_an_extra_operand():
    """The detector above catches a *replaced* operand. It misses a
    *spurious extra* one, which is how base64 hid: `base64 -w 0 file`
    collected both "0" and the file, so the error still named the file
    while the read of "0" failed silently and the command produced
    nothing. The sharper question is whether a flag whose value changes
    nothing produces the same output as no flag at all.
    """
    s = sh()
    run(s, "printf 'hello\n' > /tmp/w.txt")
    plain = run(s, "base64 /tmp/w.txt")
    for opt in ("-w 76", "-w0", "-w 0"):
        got = run(s, "base64 %s /tmp/w.txt" % opt)
        eq("base64 %s matches the unflagged encode" % opt,
           got.strip(), plain.strip())
    eq("and from stdin too",
       run(s, "echo hello | base64 -w 0").strip(), "aGVsbG8K")


def t_base64_decodes_when_the_flags_are_bundled():
    """`base64 -di` is the loader idiom, because -i tolerates the line
    noise a copy-paste leaves. Testing for the exact token "-d" missed
    every bundled form, so -di encoded instead of decoding."""
    s = sh()
    payload = "IyEvYmluL3NoCmVjaG8gZGVjb2RlZAo="
    for form in ("-d", "--decode", "-di", "-id"):
        out = run(s, "echo %s | base64 %s" % (payload, form))
        check("base64 %s decodes" % form, out.startswith("#!/bin/sh"),
              out[:40])
    eq("and the pipe-to-shell idiom runs it",
       run(s, "echo %s | base64 -d | sh" % payload).strip(), "decoded")
    eq("whitespace is ignored with -i",
       run(s, "echo 'aGVs bG8=' | base64 -di").strip(), "hello")


def t_base64_rejects_what_it_cannot_decode():
    """It decoded garbage and exited 0, so a truncated stage looked like a
    clean one. coreutils writes the groups it managed and then fails."""
    s = sh()
    out = run(s, "echo not-valid-b64! | base64 -d")
    check("says invalid input", "base64: invalid input" in out, out[:60])
    eq("and fails", s.last_rc, 1)
    out = run(s, "echo aGVsbG8= | base64 -d")
    eq("a good payload still succeeds", (out.strip(), s.last_rc),
       ("hello", 0))


def t_a_neutral_flag_changes_nothing():
    """The sharpened invariant, run across the commands it was built for.

    A flag whose value is the default must produce exactly the output the
    unflagged command produces. This is what catches the extra-operand
    shape, where the value is collected *alongside* the real operand
    rather than instead of it -- so the operand is still named, the
    detector's first question passes, and the command quietly does extra
    work on a path that does not exist.
    """
    s = sh()
    run(s, "printf 'bbb\naaa\nccc\n' > /tmp/n.txt")
    run(s, "printf 'a:b\n' > /tmp/j.txt")
    pairs = [
        ("du -s /tmp", "du -s -B 1024 /tmp"),
        ("du -s /tmp", "du -s -t 0 /tmp"),
        ("du -s /tmp", "du -s --threshold 0 /tmp"),
        ("du -s /tmp", "du -s --exclude nope /tmp"),
        ("du -s /tmp", "du -s -d 0 /tmp"),
        ("df /", "df -B 1024 /"),
        ("df /", "df --block-size 1024 /"),
        ("ls /tmp", "ls -I nope /tmp"),
        ("sort /tmp/n.txt", "sort -k 1 /tmp/n.txt"),
        ("sort /tmp/n.txt", "sort -S 1M /tmp/n.txt"),
        ("uniq /tmp/n.txt", "uniq -f 0 /tmp/n.txt"),
        ("head /tmp/n.txt", "head -n 10 /tmp/n.txt"),
        ("od -c /tmp/n.txt", "od -A o -c /tmp/n.txt"),
        ("nl /tmp/n.txt", "nl -w 6 /tmp/n.txt"),
        ("base64 /tmp/n.txt", "base64 -w 76 /tmp/n.txt"),
    ]
    for plain, flagged in pairs:
        a = run(s, plain)
        b = run(s, flagged)
        eq("%s == %s" % (flagged, plain), b, a)


def t_no_command_reports_a_flag_value_as_a_missing_file():
    """The symptom the invariant above exists to catch, stated directly."""
    s = sh()
    run(s, "printf 'a:b\n' > /tmp/j.txt")
    for cmd in ("du -s -B 1024 /tmp", "du -s -t 0 /tmp",
                "df -B 1024 /", "df --block-size 1024 /",
                "ls -I nope /tmp", "join -t : /tmp/j.txt /tmp/j.txt",
                "base64 -w 0 /tmp/j.txt", "paste -d , /tmp/j.txt"):
        out = run(s, cmd + " 2>&1")
        check("%s does not report a missing file" % cmd,
              "No such file" not in out and "cannot access" not in out,
              out[:70])


def t_the_separators_actually_separate():
    """Consuming the value is half of it; join -t and paste -d have to use
    theirs."""
    s = sh()
    run(s, "printf 'a:1\n' > /tmp/x.txt; printf 'a:2\n' > /tmp/y.txt")
    out = run(s, "join -t : /tmp/x.txt /tmp/y.txt")
    check("join -t uses the separator", out.strip() == "a:1:2", out[:40])
    run(s, "printf '1\n' > /tmp/p1; printf 'x\n' > /tmp/p2")
    eq("paste -d uses the delimiter",
       run(s, "paste -d , /tmp/p1 /tmp/p2").strip(), "1,x")


def t_a_missing_file_fails_the_way_coreutils_fails():
    """Exit codes matter here because the payloads are built from ||
    chains: `nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo` picks
    its branch on the status, so a command that fails with 0 sends the
    caller down the wrong path silently.

    _input works out what it could not read and records it, and all eight
    of its callers were discarding that. Five happened to produce the
    right status by another route; three -- uniq, rev and base64 --
    returned 0 for a file that does not exist.
    """
    s = sh()
    for cmd, rc in (("uniq /nonexistent-zz", 1), ("rev /nonexistent-zz", 1),
                    ("base64 /nonexistent-zz", 1),
                    ("base64 -d /nonexistent-zz", 1),
                    ("wc /nonexistent-zz", 1), ("sort /nonexistent-zz", 2),
                    ("cut -d: -f1 /nonexistent-zz", 1)):
        run(s, cmd)
        eq("%s exits %d" % (cmd, rc), s.last_rc, rc)


def t_the_error_names_the_program_and_the_file():
    s = sh()
    for cmd, want in (
            ("uniq /nonexistent-zz",
             "uniq: /nonexistent-zz: No such file or directory"),
            ("base64 /nonexistent-zz",
             "base64: /nonexistent-zz: No such file or directory"),
            # rev words it differently from the rest of coreutils.
            ("rev /nonexistent-zz",
             "rev: cannot open /nonexistent-zz: No such file or directory")):
        out = run(s, cmd + " 2>&1")
        eq(cmd, out.strip(), want)


def t_a_file_that_exists_still_succeeds():
    """The fix has to not turn every named file into a failure -- which is
    exactly what it did on the first attempt, because _input's second
    return value is the file list, not a status."""
    s = sh()
    for cmd, rc in (("uniq /etc/hostname", 0), ("rev /etc/hostname", 0),
                    ("base64 /etc/hostname", 0), ("echo hi | uniq", 0),
                    ("echo hi | rev", 0), ("echo hi | base64", 0)):
        out = run(s, cmd)
        eq("%s exits %d" % (cmd, rc), s.last_rc, rc)
        check("%s produced output" % cmd, out.strip() != "", repr(out[:20]))


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
