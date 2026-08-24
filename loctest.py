#!/usr/bin/env python3
"""What encoding is this box in, and which files say so?

The sibling of the zone question, and it failed the same way. `locale`
names C.UTF-8 in every category, `locale -a` lists the three locales a
glibc image has, and `dpkg -L libc-bin` lists /usr/bin/iconv -- and behind
all of that:

    iconv -l                       iconv 2.41 / Usage: iconv [OPTION]...
    iconv --help                   iconv 2.41 / Usage: iconv [OPTION]...
    printf abc | iconv -f UTF-8 -t ASCII    iconv 2.41 / Usage: ...  rc 1

Every invocation returned the unimplemented-binary fallback. A binary the
package manager owns, that `which` resolves, and that cannot do the one
thing it exists for -- reachable in one command, and decode chains reach
for it by habit.

`locale` had the matching problem: it ignored every argument. `locale
charmap`, `locale LC_TIME`, `locale -k LC_TIME`, `locale -c LC_TIME` and
`locale nosuchkeyword` all printed the same dump of environment variables,
the last of them exiting 0 where the real one refuses by name. And
`locale -m` listed three charmaps out of 236.

Underneath, the data files were not there either: /usr/lib/locale/C.utf8
held one of the twelve category files glibc compiles, /usr/share/i18n did
not exist, and neither did /etc/locale.gen or /etc/default/locale -- on a
box that answers `locale` in full.

Every list, keyword value, file name and size here was read off the guest,
which runs the same C.UTF-8; see localedb.py.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402
import localedb                                                 # noqa: E402

PASS, FAIL = 0, 0
FAILURES = []


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
    else:
        FAIL += 1
        FAILURES.append("%-56s %s" % (name, detail))


S = fs.Shell(fs.VFS())
S.exec_mode = True


def R(cmd):
    S._err = []
    out = S.run(cmd)
    return out or "", "".join(S._err), S.last_rc


# ---------------------------------------------------------------------------
# iconv is a program, not a usage message
# ---------------------------------------------------------------------------
def t_iconv_lists_what_it_knows():
    out, err, rc = R("iconv -l")
    check("iconv -l exits 0", rc == 0, "rc=%s %s" % (rc, err[:50]))
    names = out.split()
    check("it lists the guest's 1180 encodings", len(names) == 1180,
          str(len(names)))
    check("in the guest's order", names[:3] == ["437//", "500//", "500V1//"],
          str(names[:3]))
    for want in ("UTF-8//", "ASCII//", "ISO-8859-1//", "UTF-16//"):
        check("iconv -l has %s" % want, want in names, "missing")
    check("--list is the same flag", R("iconv --list")[0] == out, "differs")
    check("no usage message leaked in", "Usage:" not in out + err,
          (out + err)[:60])


def t_iconv_help_is_argps():
    out, _e, rc = R("iconv --help")
    check("iconv --help exits 0", rc == 0, "rc=%s" % rc)
    check("it is the argp help, not the fallback",
          out.startswith("Usage: iconv [OPTION...] [FILE...]"), out[:60])
    check("it documents -f, -t and -l",
          all(f in out for f in ("--from-code", "--to-code", "--list")),
          "missing a flag")
    usage, _e, rc = R("iconv --usage")
    check("iconv --usage is the short form",
          usage.startswith("Usage: iconv [-lcs?V]"), usage[:50])
    check("and they are different texts", usage != out, "identical")


def t_iconv_converts():
    out, err, rc = R("printf abc | iconv -f UTF-8 -t ASCII")
    check("a plain conversion exits 0", rc == 0, "rc=%s %s" % (rc, err[:40]))
    check("and passes the bytes through", out == "abc", repr(out))
    # Latin-1: the acute e becomes one byte, 0xe9.
    hexed = R("printf 'caf\\xc3\\xa9' | iconv -f UTF-8 -t ISO-8859-1 "
              "| od -An -tx1")[0].split()
    check("UTF-8 to ISO-8859-1 is a real re-encoding",
          hexed == ["63", "61", "66", "e9"], str(hexed))
    # A character the target cannot hold: glibc reports EILSEQ, counts the
    # position in input bytes, and flushes what it managed.
    out, err, rc = R("printf 'caf\\xc3\\xa9' | iconv -f UTF-8 -t ASCII")
    check("an unconvertible character exits 1", rc == 1, "rc=%s" % rc)
    check("with glibc's wording and position",
          err.strip() == "iconv: illegal input sequence at position 3",
          err.strip()[:70])
    check("and the part it managed is still on stdout", out == "caf",
          repr(out))
    # //TRANSLIT is a transliteration, not a row of question marks.
    out, _e, rc = R("printf 'caf\\xc3\\xa9' | iconv -f UTF-8 "
                    "-t ASCII//TRANSLIT")
    check("//TRANSLIT transliterates", out == "cafe", repr(out))
    check("//TRANSLIT exits 0", rc == 0, "rc=%s" % rc)
    out, _e, rc = R("printf 'caf\\xc3\\xa9' | iconv -c -f UTF-8 -t ASCII")
    check("-c drops what it cannot convert", (out, rc) == ("caf", 0),
          "%r rc=%s" % (out, rc))


def t_iconv_refuses_what_it_does_not_know():
    out, err, rc = R("printf abc | iconv -f UTF-8 -t NOSUCHENC")
    check("an unknown target exits 1", rc == 1, "rc=%s" % rc)
    check("named, in glibc's quoting",
          "iconv: conversion to `NOSUCHENC' is not supported"
          in err, err[:70])
    check("with the try-help line", "Try `iconv --help'" in err, err[:70])
    check("and no output", out == "", repr(out))
    err = R("printf abc | iconv -f NOSUCHENC -t UTF-8")[1]
    check("an unknown source says `from'",
          "conversion from `NOSUCHENC' is not supported" in err, err[:70])
    # Everything it accepts has to be a name it also lists.
    listed = set(R("iconv -l")[0].split())
    for enc in ("UTF-8", "ASCII", "ISO-8859-1", "UTF-16", "CP1252"):
        check("iconv -l knows the name it accepts: %s" % enc,
              enc + "//" in listed, "%s not listed" % enc)


# ---------------------------------------------------------------------------
# locale answers the question it was asked
# ---------------------------------------------------------------------------
def t_locale_takes_a_category():
    plain = R("locale")[0]
    out, _e, rc = R("locale LC_TIME")
    check("locale LC_TIME exits 0", rc == 0, "rc=%s" % rc)
    check("it is not the variable dump", out != plain, "same as bare locale")
    check("it opens with the abbreviated day names",
          out.startswith("Sun;Mon;Tue;Wed;Thu;Fri;Sat\n"), out[:50])
    check("values are unquoted without -k", '"' not in out.splitlines()[0],
          out.splitlines()[0][:50])
    keyed = R("locale -k LC_TIME")[0]
    check("-k names each keyword",
          keyed.startswith('abday="Sun;Mon;Tue;Wed;Thu;Fri;Sat"'),
          keyed[:50])
    check("-k has the same number of lines as the bare form",
          len(keyed.splitlines()) == len(out.splitlines()),
          "%d vs %d" % (len(keyed.splitlines()), len(out.splitlines())))
    catted = R("locale -c LC_TIME")[0]
    check("-c prints the category first",
          catted.splitlines()[0] == "LC_TIME", catted[:40])
    check("-c then the same values", catted.splitlines()[1:]
          == out.splitlines(), catted[:60])


def t_locale_takes_a_keyword():
    check("a keyword by name works",
          R("locale abday")[0].strip() == "Sun;Mon;Tue;Wed;Thu;Fri;Sat",
          R("locale abday")[0].strip()[:50])
    check("locale charmap is UTF-8", R("locale charmap")[0].strip()
          == "UTF-8", R("locale charmap")[0].strip())
    out, err, rc = R("locale nosuchkeyword")
    check("an unknown name exits 1", rc == 1, "rc=%s" % rc)
    check("and says so by name",
          err.strip() == 'locale: unknown name "nosuchkeyword"', err[:60])
    check("printing nothing", out == "", repr(out))
    # A bad name among good ones still lets the good ones through.
    out, err, rc = R("locale abday nosuchkeyword charmap")
    check("one bad name does not swallow the others",
          out.splitlines() == ["Sun;Mon;Tue;Wed;Thu;Fri;Sat", "UTF-8"],
          str(out.splitlines()))
    check("and the exit code still reports it", rc == 1, "rc=%s" % rc)


def t_locale_m_matches_the_charmap_directory():
    out, _e, rc = R("locale -m")
    names = out.split()
    check("locale -m exits 0", rc == 0, "rc=%s" % rc)
    check("it lists the guest's 236 charmaps", len(names) == 236,
          str(len(names)))
    check("starting where the guest's starts",
          names[:2] == ["ANSI_X3.110-1983", "ANSI_X3.4-1968"], str(names[:2]))
    # ...and the directory it reads holds a file for each, gzipped, which
    # is how Debian ships them. Three of the 236 are names glibc knows
    # without a file of their own; naming them here is cheaper than
    # pretending the two lists are the same length.
    have = {f[:-3] if f.endswith(".gz") else f
            for f in R("ls /usr/share/i18n/charmaps")[0].split()}
    check("the charmaps are gzipped, as Debian ships them",
          all(f.endswith(".gz")
              for f in R("ls /usr/share/i18n/charmaps")[0].split()),
          R("ls /usr/share/i18n/charmaps")[0].split()[:2])
    check("every file in the directory is a charmap locale -m names",
          not (have - set(names)), str(sorted(have - set(names))[:4]))
    check("and only these three are named without one",
          sorted(set(names) - have) == ["MAC_CENTRALEUROPE",
                                        "NF_Z_62-010_(1973)",
                                        "WIN-SAMI-2"],
          str(sorted(set(names) - have)[:4]))
    check("locale charmap names one of them",
          R("locale charmap")[0].strip() in names,
          R("locale charmap")[0].strip())


# ---------------------------------------------------------------------------
# ...and the files behind all of it
# ---------------------------------------------------------------------------
def t_the_locale_data_is_on_disk():
    files = R("ls /usr/lib/locale/C.utf8")[0].split()
    check("C.utf8 has the twelve category files glibc compiles",
          len(files) == 12, str(len(files)))
    for cat in ("LC_CTYPE", "LC_TIME", "LC_COLLATE", "LC_MESSAGES"):
        check("C.utf8 has %s" % cat, cat in files, str(sorted(files)[:4]))
    size = R("stat -c %s /usr/lib/locale/C.utf8/LC_CTYPE")[0].strip()
    check("LC_CTYPE is the size the guest's is", size == "367708", size)
    # locale -a names exactly what is on disk, plus the two builtins.
    listed = set(R("locale -a")[0].split())
    check("locale -a is C, C.utf8 and POSIX", listed == {"C", "C.utf8",
                                                         "POSIX"},
          str(sorted(listed)))
    check("and C.utf8 is the directory that exists",
          "C.utf8" in R("ls /usr/lib/locale")[0].split(),
          R("ls /usr/lib/locale")[0][:40])

    check("/usr/share/i18n exists",
          set(R("ls /usr/share/i18n")[0].split())
          == {"SUPPORTED", "charmaps", "locales"},
          R("ls /usr/share/i18n")[0][:50])
    check("with the guest's file counts",
          len(R("ls /usr/share/i18n/charmaps")[0].split()) == 233
          and len(R("ls /usr/share/i18n/locales")[0].split()) == 371,
          "%d / %d" % (len(R("ls /usr/share/i18n/charmaps")[0].split()),
                       len(R("ls /usr/share/i18n/locales")[0].split())))


def t_the_package_story_holds():
    row = [l for l in R("dpkg -l locales")[0].splitlines()
           if l.startswith("ii")]
    check("dpkg says locales is installed", bool(row),
          R("dpkg -l locales")[1][:50])
    if row:
        check("with a real description", "National Language" in row[0],
              row[0][-40:])
    # libc-bin owns iconv and locale, and ships the rest of its /usr/bin set.
    owned = R("dpkg -L libc-bin")[0].split()
    for b in ("/usr/bin/iconv", "/usr/bin/locale", "/usr/bin/localedef",
              "/usr/bin/getent", "/usr/bin/ldd", "/usr/bin/pldd",
              "/usr/bin/tzselect"):
        check("libc-bin ships %s" % b, b in owned, "not listed")
        check("...and it is there", R("test -x %s" % b)[2] == 0, "missing")
    check("dpkg -S finds the owner of iconv",
          "libc-bin" in R("dpkg -S /usr/bin/iconv")[0],
          R("dpkg -S /usr/bin/iconv")[0][:50])
    # The config files, and the symlink Debian uses instead of a second copy.
    check("/etc/locale.conf holds the answer",
          R("cat /etc/locale.conf")[0].strip() == "LANG=C.UTF-8",
          R("cat /etc/locale.conf")[0][:40])
    link = R("readlink /etc/default/locale")[0].strip()
    check("/etc/default/locale points at it", link == "../locale.conf", link)
    check("and reading it through the link gives the same line",
          R("cat /etc/default/locale")[0].strip() == "LANG=C.UTF-8",
          R("cat /etc/default/locale")[0][:40])
    check("the LANG in the environment is the one that file names",
          R("echo $LANG")[0].strip() == "C.UTF-8",
          R("echo $LANG")[0].strip())
    check("/etc/locale.gen is there and is the real thing",
          R("grep -c '^#' /etc/locale.gen")[0].strip().isdigit()
          and int(R("grep -c '^#' /etc/locale.gen")[0]) > 400,
          R("grep -c '^#' /etc/locale.gen")[0].strip())


TESTS = [t_iconv_lists_what_it_knows,
         t_iconv_help_is_argps,
         t_iconv_converts,
         t_iconv_refuses_what_it_does_not_know,
         t_locale_takes_a_category,
         t_locale_takes_a_keyword,
         t_locale_m_matches_the_charmap_directory,
         t_the_locale_data_is_on_disk,
         t_the_package_story_holds]


def main():
    for fn in TESTS:
        try:
            fn()
        except Exception as exc:                       # pragma: no cover
            check(fn.__name__ + " raised", False, repr(exc)[:90])
    for line in FAILURES:
        print("  FAIL " + line)
    print("passed %d, failed %d" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
