#!/usr/bin/env python3
"""Does chmod read its own mode argument the way chmod does?

Seventieth coherence sweep. The axis is the chmod argument itself --
not what the mode ends up being, which modetest already covers, but the
parse that decides whether a word is an option, a mode, or neither. Two
readers were answering that question and they were not the same reader:
the generic coreutils option gate had one rule, written as a regex over
`rwxXst`, and cmd_chmod had another, written as "every character is in
cfvR". Neither is the rule getopt applies.

chmod carries the mode letters inside its own option string, as options
that take an optional argument. The first mode character in an element
therefore makes the *whole element* the mode -- option letters ahead of
it included. That single fact settles every shape below, and the two
rules we had settled none of them:

  * `chmod -x,-w f` and `chmod -u+x f` are modes. Both were
    "chmod: invalid option -- 'x'", rc 1, file unchanged.
  * `chmod -Rx f` is "invalid mode: \u2018-Rx\u2019", not a recursive -x. So are
    -cx, -fx and -vx. We said "invalid option -- 'x'".
  * `chmod -qx f` is still "invalid option -- 'q'": an unknown letter
    wins even when a mode character follows it.
  * `chmod -755 f` clears those bits and `chmod =755 f` sets exactly
    them. Both were invalid modes here. Neither is umask-limited --
    `chmod -2` on a 0777 file gives 0775 under umask 022, which masks
    that very bit -- while `chmod u-0` really is an invalid mode.

chmod states the grammar in its own --help, and it is the whole rule:

    Each MODE is of the form '[ugoa]*([-+=]([rwxXst]*|[ugo]))+|[-+=][0-7]+'

Both halves were missing here: the `+` that allows chained operators, and
the `[-+=][0-7]+` alternative entirely. The octal part has no length limit
and does have a value limit -- `chmod 0000755` is 0755 and `chmod 77777`
is an invalid mode.

The option letters matter as much as the mode letters, because the
classifier chooses between them. chmod takes -h, and -H/-L/-P alongside
-R; the set here was cfvR, which cost nothing while it was a fallback and
cost four documented options the moment it became the answer. cuhelptest
caught that in the gate, out of chmod's own help text.

Underneath the parse, four more disagreements between what we computed
and what the box computes:

  * chained operators in one clause. `u+rw-x` and `+x-w` are one clause
    with two changes; we rejected both as invalid modes.
  * `=` with no who-class. It was left umask-free, so `chmod =rwx` gave
    0777 where the real one gives 0755: a bare `=` clears every bit and
    then sets only the ones the umask leaves.
  * `+X` on a directory. X was keyed on "already has an execute bit"
    alone, so `chmod -R a+rX tree` -- the ordinary way to open a tree up
    -- left every directory in it unenterable.
  * a missing operand abandoned the rest. `chmod 644 nosuch f` returned
    at nosuch and left f alone, where the real one reports nosuch,
    changes f, and still exits 1.

And two message shapes: `chmod 755` with no file names the mode it was
given ("missing operand after \u2018755\u2019"), while `chmod -x` with no
file does not, because that mode arrived as an option.

Two commands away from chmod, the same axis again: a `-m` argument is a
mode, and chmod was the only reader on the box that could read a symbolic
one. `mkdir -m` and `install -m` both did int(spec, 8) and stopped there,
so `mkdir -m u=rwx,go= staging` was an invalid mode here and a 0700
directory on the guest. install was worse: it swallowed the ValueError, so
`install -m u+x payload /usr/local/bin/x` produced 0755 in silence and
`install -m zzz` exited 0. Their starting points differ and both matter --
mkdir applies the spec to 0777 and install applies it to 0, which is why
`install -m u+x src dst` is 0100 -- and neither consults the umask.

Quoting is part of the answer. Under C.UTF-8, which is what this box's
LANG says, coreutils prints a *mode* through quote() and a *file name*
through quotef():

    chmod: invalid mode: \u2018-Rx\u2019
    chmod: cannot access 'nosuch': No such file or directory

mkdir already knew that for "File exists" and not for "invalid mode", one
function apart.

The umask warning is its own trap. GNU prints

    chmod: f: new permissions are r-xrwxrwx, not r-xr-xr-x

and exits 1 when the umask changed the outcome, but only when the
*first* clause is the bare removal. Measured: `-w,+x` warns and
`+x,-w` does not, though both land on 0577 from 0777. The guard here
matched a leading dash in any clause, so the second of that pair warned
where the box is silent.

Every expectation below was measured on the guest, coreutils 9.7, at
four umasks. Two of them were first taken under the login shell's own
umask of 002 and read as if they were 022, which is how -wx briefly
"failed": 0446 is the right answer to a question this suite does not
ask. Both umasks are in the table now.

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def sh():
    s = fs.Shell(fs.VFS(), peer="203.0.113.77")
    s.exec_mode = True
    s.run("umask 022")
    s._err.clear()
    return s


def run(s, cmd):
    out = s.run(cmd)
    err = "".join(s._err)
    s._err.clear()
    return out, err, s.last_rc


def mode(s, path):
    return run(s, "stat -c %%a %s" % path)[0].strip()


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-56s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


HELP = "Try 'chmod --help' for more information."

# (umask, starting mode, spec, resulting mode, rc, expected stderr fragment)
TABLE = [
    # the dashed forms that were refused outright
    ("022", "777", "-x",     "666", 0, ""),
    ("022", "777", "-w",     "577", 1, "new permissions are r-xrwxrwx, "
                                       "not r-xr-xr-x"),
    ("022", "777", "-r",     "333", 0, ""),
    ("022", "777", "-t",     "777", 0, ""),
    ("022", "777", "-s",     "777", 0, ""),
    ("022", "777", "-X",     "666", 0, ""),
    ("022", "777", "-rwx",   "22",  1, "new permissions are ----w--w-, "
                                       "not ---------"),
    ("022", "777", "-wx",    "466", 1, "new permissions are r--rw-rw-, "
                                       "not r--r--r--"),
    ("022", "777", "-x,-w",  "466", 1, "new permissions are r--rw-rw-, "
                                       "not r--r--r--"),
    ("022", "777", "-x-w",   "466", 1, "new permissions are r--rw-rw-, "
                                       "not r--r--r--"),
    ("022", "777", "-rw",    "133", 1, "new permissions are --x-wx-wx, "
                                       "not --x--x--x"),
    ("022", "777", "-u",     "22",  1, "new permissions are ----w--w-, "
                                       "not ---------"),
    ("022", "777", "-u+x",   "133", 1, "new permissions are --x-wx-wx, "
                                       "not --x--x--x"),
    ("022", "777", "-w,+x",  "577", 1, "new permissions are r-xrwxrwx, "
                                       "not r-xr-xr-x"),
    ("022", "777", "-w+x",   "577", 1, "new permissions are r-xrwxrwx, "
                                       "not r-xr-xr-x"),
    ("022", "777", "-g=r",   "444", 0, ""),
    ("022", "777", "-o+w",   "222", 0, ""),
    ("022", "777", "-Xt",    "666", 0, ""),
    ("022", "777", "-+x",    "777", 0, ""),
    ("022", "777", "-=r",    "444", 0, ""),
    # the warning follows the first clause, not any clause
    ("022", "777", "+x-w",   "577", 0, ""),
    ("022", "777", "+x,-w",  "577", 0, ""),
    ("022", "666", "+x-w",   "577", 0, ""),
    ("022", "666", "+x,-w",  "577", 0, ""),
    ("022", "666", "-w,+x",  "577", 1, "new permissions are r-xrwxrwx, "
                                       "not r-xr-xr-x"),
    ("022", "666", "-w",     "466", 1, "new permissions are r--rw-rw-, "
                                       "not r--r--r--"),
    ("022", "777", "u-x,-w", "477", 0, ""),
    ("022", "777", "a-x,-w", "466", 0, ""),
    ("022", "777", "=r,-w",  "444", 0, ""),
    ("022", "777", "u-w,-r", "133", 0, ""),
    ("022", "777", "+w-r",   "333", 0, ""),
    ("022", "777", "-r+w",   "333", 0, ""),
    ("022", "777", "u-w",    "577", 0, ""),
    ("022", "777", "a-x",    "666", 0, ""),
    ("022", "777", "+x",     "777", 0, ""),
    # chained operators inside one clause
    ("022", "777", "u+rw-x", "677", 0, ""),
    ("022", "777", "ug+x-w", "557", 0, ""),
    ("022", "777", "a=rw,u+x", "766", 0, ""),
    # an octal value behind an operator, and never umask-limited
    ("022", "777", "-755",   "22",  0, ""),
    ("022", "777", "-0755",  "22",  0, ""),
    ("022", "777", "-0",     "777", 0, ""),
    ("022", "777", "-7",     "770", 0, ""),
    ("022", "777", "-2",     "775", 0, ""),
    ("022", "777", "+755",   "777", 0, ""),
    ("022", "777", "=755",   "755", 0, ""),
    ("022", "000", "=777",   "777", 0, ""),
    ("022", "000", "+777",   "777", 0, ""),
    ("022", "000", "+7",     "7",   0, ""),
    # `=` with no who-class is limited by the umask; with one it is not
    ("022", "7777", "=rwx",  "755", 0, ""),
    ("022", "7777", "a=rwx", "777", 0, ""),
    ("022", "7777", "a=r",   "444", 0, ""),
    ("022", "777",  "u=rw",  "677", 0, ""),
    ("022", "4777", "=r",    "444", 0, ""),
    ("077", "777",  "=r",    "400", 0, ""),
    ("077", "4777", "=r",    "400", 0, ""),
    # the set-id and sticky bits
    ("022", "000", "+s",     "6000", 0, ""),
    ("022", "000", "+t",     "1000", 0, ""),
    ("022", "000", "+st",    "7000", 0, ""),
    ("022", "4755", "-s",    "755",  0, ""),
    ("022", "1777", "-t",    "777",  0, ""),
    # a who-less clause is the umask's business at every umask
    ("022", "000", "+w",     "200", 0, ""),
    ("022", "000", "+x",     "111", 0, ""),
    ("022", "000", "+rwx",   "755", 0, ""),
    ("077", "777", "-x",     "677", 1, "new permissions are rw-rwxrwx, "
                                       "not rw-rw-rw-"),
    ("077", "777", "-w",     "577", 1, "new permissions are r-xrwxrwx, "
                                       "not r-xr-xr-x"),
    ("077", "777", "-r",     "377", 1, "new permissions are -wxrwxrwx, "
                                       "not -wx-wx-wx"),
    ("077", "777", "-rwx",   "77",  1, "new permissions are ---rwxrwx, "
                                       "not ---------"),
    ("077", "777", "+w",     "777", 0, ""),
    ("077", "777", "+x",     "777", 0, ""),
    ("077", "777", "+rwx",   "777", 0, ""),
    ("077", "777", "+x-w",   "577", 0, ""),
    ("002", "777", "-w",     "557", 1, "new permissions are r-xr-xrwx, "
                                       "not r-xr-xr-x"),
    ("002", "777", "-rwx",   "2",   1, "new permissions are -------w-, "
                                       "not ---------"),
    ("002", "777", "-wx",    "446", 1, "new permissions are r--r--rw-, "
                                       "not r--r--r--"),
    ("002", "777", "-x,-w",  "446", 1, "new permissions are r--r--rw-, "
                                       "not r--r--r--"),
    ("002", "777", "-x",     "666", 0, ""),
    ("000", "777", "-w",     "555", 0, ""),
    ("000", "777", "-rwx",   "0",   0, ""),
]


def t_every_measured_spec_lands_where_the_box_lands():
    s = sh()
    for umask, base, spec, want, wrc, werr in TABLE:
        run(s, "umask %s" % umask)
        run(s, "rm -f /tmp/f; echo x > /tmp/f; chmod %s /tmp/f" % base)
        _out, err, rc = run(s, "chmod %s /tmp/f" % spec)
        tag = "umask %s %s %s" % (umask, base, spec)
        eq("%s: mode" % tag, mode(s, "/tmp/f"), want)
        eq("%s: rc" % tag, rc, wrc)
        if werr:
            check("%s: warns" % tag, werr in err, "got %r" % err)
        else:
            check("%s: silent" % tag, err.strip() == "", "got %r" % err)


# -- what is an option, what is a mode, what is neither ---------------------

BADMODE = ["-Rx", "-xR", "-cx", "-vx", "-fx", "-a-x", "-,x", "-ux", "u-0",
           "-Ht", "-hx", "77777", "10000", "-77777", "8", "09"]
BADOPT = [("-q", "q"), ("-Z", "Z"), ("-qx", "q"), ("-Rq", "q"), ("-fq", "q")]
TRAVERSAL = ["-h", "-H", "-L", "-P", "--dereference", "--no-dereference"]


def t_an_option_letter_before_a_mode_letter_is_a_bad_mode():
    """`chmod -Rx f` is not a recursive -x, and never was."""
    s = sh()
    run(s, "echo x > /tmp/f")
    for spec in BADMODE:
        run(s, "chmod 777 /tmp/f")
        _out, err, rc = run(s, "chmod %s /tmp/f" % spec)
        check("%s: invalid mode" % spec,
              ("chmod: invalid mode: \u2018%s\u2019" % spec) in err
              and HELP in err,
              "got %r" % err)
        eq("%s: rc" % spec, rc, 1)
        eq("%s: file untouched" % spec, mode(s, "/tmp/f"), "777")


def t_an_unknown_letter_wins_over_a_mode_letter_behind_it():
    s = sh()
    run(s, "echo x > /tmp/f")
    for spec, ch in BADOPT:
        run(s, "chmod 777 /tmp/f")
        _out, err, rc = run(s, "chmod %s /tmp/f" % spec)
        check("%s: invalid option" % spec,
              ("chmod: invalid option -- '%s'" % ch) in err and HELP in err,
              "got %r" % err)
        eq("%s: rc" % spec, rc, 1)
        eq("%s: file untouched" % spec, mode(s, "/tmp/f"), "777")


def t_the_symlink_traversal_options_are_options():
    """-h, and -H/-L/-P for -R. Documented, and refused here for a while."""
    s = sh()
    run(s, "echo x > /tmp/f")
    for opt in TRAVERSAL:
        run(s, "chmod 777 /tmp/f")
        _out, err, rc = run(s, "chmod %s 755 /tmp/f" % opt)
        eq("chmod %s 755: mode" % opt, mode(s, "/tmp/f"), "755")
        eq("chmod %s 755: rc" % opt, rc, 0)
        eq("chmod %s 755: silent" % opt, err.strip(), "")


def t_an_octal_mode_may_be_any_length_but_not_any_value():
    s = sh()
    run(s, "echo x > /tmp/f")
    for spec, want in (("00755", "755"), ("0000755", "755"), ("755", "755"),
                       ("07777", "7777"), ("-00755", "22"), ("+0007", "777")):
        run(s, "chmod 777 /tmp/f")
        _out, err, rc = run(s, "chmod %s /tmp/f" % spec)
        eq("chmod %s" % spec, mode(s, "/tmp/f"), want)
        eq("chmod %s: rc" % spec, rc, 0)
        eq("chmod %s: silent" % spec, err.strip(), "")


def t_real_options_still_work_beside_a_dashed_mode():
    s = sh()
    run(s, "rm -rf /tmp/d; mkdir -p /tmp/d/sub; echo x > /tmp/d/sub/g")
    run(s, "chmod 777 /tmp/d /tmp/d/sub /tmp/d/sub/g")
    _out, err, rc = run(s, "chmod -R -w /tmp/d")
    eq("-R -w: dir", mode(s, "/tmp/d"), "577")
    eq("-R -w: leaf", mode(s, "/tmp/d/sub/g"), "577")
    eq("-R -w: rc", rc, 1)
    check("-R -w: warns per file", err.count("new permissions are") == 3,
          "got %r" % err)


def t_two_dashed_modes_are_both_applied():
    """`chmod -x -w f` is the same command as `chmod -x,-w f`."""
    s = sh()
    run(s, "echo x > /tmp/f; chmod 777 /tmp/f")
    _out, err, rc = run(s, "chmod -x -w /tmp/f")
    eq("-x -w: mode", mode(s, "/tmp/f"), "466")
    eq("-x -w: rc", rc, 1)
    check("-x -w: warns once", err.count("new permissions are") == 1,
          "got %r" % err)


def t_a_number_after_a_dashed_mode_is_an_operand():
    """The mode came from an option, so 644 is a file name."""
    s = sh()
    run(s, "echo x > /tmp/f; chmod 777 /tmp/f")
    _out, err, rc = run(s, "chmod -x 644 /tmp/f")
    check("-x 644 f: names 644",
          "chmod: cannot access '644': No such file or directory" in err,
          "got %r" % err)
    eq("-x 644 f: f still changed", mode(s, "/tmp/f"), "666")
    eq("-x 644 f: rc", rc, 1)


def t_a_dashed_mode_after_dashdash_is_the_mode_operand():
    s = sh()
    run(s, "echo x > /tmp/f; chmod 777 /tmp/f")
    _out, err, rc = run(s, "chmod -- -x /tmp/f")
    eq("-- -x: mode", mode(s, "/tmp/f"), "666")
    eq("-- -x: rc", rc, 0)
    eq("-- -x: silent", err.strip(), "")


# -- operands ---------------------------------------------------------------

def t_a_missing_file_does_not_abandon_the_others():
    s = sh()
    run(s, "echo x > /tmp/f; chmod 777 /tmp/f")
    _out, err, rc = run(s, "chmod 644 /tmp/nosuch /tmp/f")
    check("missing operand named",
          "chmod: cannot access '/tmp/nosuch': No such file or directory"
          in err, "got %r" % err)
    eq("later operand still changed", mode(s, "/tmp/f"), "644")
    eq("rc", rc, 1)


def t_missing_operand_names_the_mode_only_when_it_was_one():
    s = sh()
    _out, err, rc = run(s, "chmod 755")
    check("chmod 755: names the mode",
          "chmod: missing operand after \u2018755\u2019" in err
          and HELP in err,
          "got %r" % err)
    eq("chmod 755: rc", rc, 1)
    _out, err, rc = run(s, "chmod -x")
    check("chmod -x: does not name it",
          "chmod: missing operand" in err and "after" not in err,
          "got %r" % err)
    eq("chmod -x: rc", rc, 1)
    _out, err, rc = run(s, "chmod")
    check("chmod: missing operand",
          "chmod: missing operand" in err and "after" not in err,
          "got %r" % err)
    eq("chmod: rc", rc, 1)


# -- X is about directories too ---------------------------------------------

def t_capital_x_reaches_directories():
    s = sh()
    run(s, "rm -rf /tmp/d; mkdir -p /tmp/d; chmod 600 /tmp/d")
    run(s, "chmod a+rX /tmp/d")
    eq("dir 600 a+rX", mode(s, "/tmp/d"), "755")
    run(s, "rm -f /tmp/h; echo x > /tmp/h; chmod 600 /tmp/h; "
           "chmod a+rX /tmp/h")
    eq("file 600 a+rX", mode(s, "/tmp/h"), "644")
    run(s, "chmod 700 /tmp/h; chmod a+rX /tmp/h")
    eq("file 700 a+rX", mode(s, "/tmp/h"), "755")


def t_recursive_capital_x_opens_a_tree():
    """`chmod -R a+rX` is how a tree is opened up; it has to reach in."""
    s = sh()
    run(s, "rm -rf /tmp/d; mkdir -p /tmp/d/sub; echo x > /tmp/d/sub/g")
    run(s, "chmod 600 /tmp/d /tmp/d/sub /tmp/d/sub/g")
    run(s, "chmod -R a+rX /tmp/d")
    eq("-R a+rX: top", mode(s, "/tmp/d"), "755")
    eq("-R a+rX: sub", mode(s, "/tmp/d/sub"), "755")
    eq("-R a+rX: file", mode(s, "/tmp/d/sub/g"), "644")


# -- the two readers must stay one ------------------------------------------

def t_the_gate_and_chmod_classify_the_same_words():
    """The option gate runs before cmd_chmod; both must read a word alike.

    This is the defect itself: one said "-x is an option" and the other
    said "-x is an operand", and only the first one got to speak.
    """
    s = sh()
    for word, kind in (("-x", "mode"), ("-w", "mode"), ("-rwx", "mode"),
                       ("-x,-w", "mode"), ("-u+x", "mode"), ("-755", "mode"),
                       ("-R", "opt"), ("-cv", "opt"), ("-Rfv", "opt"),
                       ("-h", "opt"), ("-H", "opt"), ("-L", "opt"),
                       ("-P", "opt"), ("-Ht", "badmode"), ("-hx", "badmode"),
                       ("-Rx", "badmode"), ("-cx", "badmode"),
                       ("-q", "q"), ("-qx", "q"), ("-Rq", "q")):
        eq("classify %s" % word, fs.Shell._chmod_dash_kind(word), kind)
    run(s, "echo x > /tmp/f; chmod 777 /tmp/f")
    _out, err, _rc = run(s, "chmod -x /tmp/f")
    check("a mode never reaches the option gate",
          "invalid option" not in err, "got %r" % err)


# -- the other two readers of a mode argument -------------------------------

MKDIR_M = [("700", "700"), ("u+rwx", "777"), ("u=rwx,go=", "700"),
           ("a+rwx", "777"), ("777", "777"), ("+x", "777"),
           ("u+rw,g+r", "777")]
INSTALL_M = [("700", "700"), ("u+x", "100"), ("u=rwx,go=rx", "755")]


def t_mkdir_m_reads_a_symbolic_mode():
    """From 0777, as a directory, with the umask ignored."""
    s = sh()
    for spec, want in MKDIR_M:
        run(s, "rm -rf /tmp/d")
        _out, err, rc = run(s, "mkdir -m %s /tmp/d" % spec)
        eq("mkdir -m %s" % spec, mode(s, "/tmp/d"), want)
        eq("mkdir -m %s: rc" % spec, rc, 0)
        eq("mkdir -m %s: silent" % spec, err.strip(), "")
    run(s, "umask 077; rm -rf /tmp/d2")
    run(s, "mkdir -m 777 /tmp/d2")
    eq("umask 077: -m is not masked", mode(s, "/tmp/d2"), "777")
    run(s, "umask 077; rm -rf /tmp/d3")
    run(s, "mkdir -m u+rwx /tmp/d3")
    eq("umask 077: symbolic -m is not masked", mode(s, "/tmp/d3"), "777")


def t_mkdir_m_names_a_mode_it_cannot_read():
    s = sh()
    run(s, "rm -rf /tmp/d")
    _out, err, rc = run(s, "mkdir -m zzz /tmp/d")
    eq("mkdir -m zzz: message", err.strip(),
       "mkdir: invalid mode \u2018zzz\u2019")
    eq("mkdir -m zzz: rc", rc, 1)
    _out, _err, rc = run(s, "ls -d /tmp/d")
    check("mkdir -m zzz: no directory", rc != 0, "it was created anyway")


def t_install_m_reads_a_symbolic_mode_from_zero():
    """`install -m u+x src dst` is 0100, not 0755 with a bit added."""
    s = sh()
    run(s, "echo hi > /tmp/src")
    for spec, want in INSTALL_M:
        run(s, "rm -f /tmp/dst")
        _out, err, rc = run(s, "install -m %s /tmp/src /tmp/dst" % spec)
        eq("install -m %s" % spec, mode(s, "/tmp/dst"), want)
        eq("install -m %s: rc" % spec, rc, 0)
        eq("install -m %s: silent" % spec, err.strip(), "")
    run(s, "rm -f /tmp/dst; install /tmp/src /tmp/dst")
    eq("install without -m", mode(s, "/tmp/dst"), "755")


def t_install_m_never_silently_uses_the_default():
    """The swallowed ValueError: a mode it could not read exited 0 at 0755."""
    s = sh()
    run(s, "echo hi > /tmp/src; rm -f /tmp/dst")
    _out, err, rc = run(s, "install -m zzz /tmp/src /tmp/dst")
    eq("install -m zzz: message", err.strip(),
       "install: invalid mode \u2018zzz\u2019")
    eq("install -m zzz: rc", rc, 1)
    _out, _err, rc = run(s, "ls /tmp/dst")
    check("install -m zzz: nothing installed", rc != 0, "dst exists")


def t_install_d_applies_its_mode():
    s = sh()
    run(s, "rm -rf /tmp/dd; install -d -m u+rwx /tmp/dd")
    eq("install -d -m u+rwx", mode(s, "/tmp/dd"), "700")
    run(s, "rm -rf /tmp/dd2; install -d -m 700 /tmp/dd2")
    eq("install -d -m 700", mode(s, "/tmp/dd2"), "700")
    run(s, "rm -rf /tmp/dd3; install -d /tmp/dd3")
    eq("install -d without -m", mode(s, "/tmp/dd3"), "755")


def t_a_mode_and_a_file_name_are_quoted_differently():
    """quote() for the mode, quotef() for the file -- one command, two."""
    s = sh()
    run(s, "echo x > /tmp/f")
    _out, err, _rc = run(s, "chmod -Rx /tmp/f")
    check("mode uses \u2018 \u2019", "\u2018-Rx\u2019" in err, "got %r" % err)
    _out, err, _rc = run(s, "chmod 644 /tmp/nosuch")
    check("file name uses '", "'/tmp/nosuch'" in err, "got %r" % err)
    run(s, "rm -rf /tmp/d; mkdir /tmp/d")
    _out, err, _rc = run(s, "mkdir /tmp/d")
    check("mkdir File exists uses \u2018 \u2019",
          "\u2018/tmp/d\u2019" in err, "got %r" % err)
    _out, err, _rc = run(s, "mkdir -m zzz /tmp/d9")
    check("mkdir invalid mode uses \u2018 \u2019",
          "\u2018zzz\u2019" in err, "got %r" % err)


TESTS = [t_every_measured_spec_lands_where_the_box_lands,
         t_an_option_letter_before_a_mode_letter_is_a_bad_mode,
         t_an_unknown_letter_wins_over_a_mode_letter_behind_it,
         t_real_options_still_work_beside_a_dashed_mode,
         t_two_dashed_modes_are_both_applied,
         t_a_number_after_a_dashed_mode_is_an_operand,
         t_a_dashed_mode_after_dashdash_is_the_mode_operand,
         t_a_missing_file_does_not_abandon_the_others,
         t_missing_operand_names_the_mode_only_when_it_was_one,
         t_capital_x_reaches_directories,
         t_recursive_capital_x_opens_a_tree,
         t_the_gate_and_chmod_classify_the_same_words,
         t_the_symlink_traversal_options_are_options,
         t_an_octal_mode_may_be_any_length_but_not_any_value,
         t_mkdir_m_reads_a_symbolic_mode,
         t_mkdir_m_names_a_mode_it_cannot_read,
         t_install_m_reads_a_symbolic_mode_from_zero,
         t_install_m_never_silently_uses_the_default,
         t_install_d_applies_its_mode,
         t_a_mode_and_a_file_name_are_quoted_differently]


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
