"""A real sed, for the shell emulator.

The previous one handled `s///` and little else: `d`, `a`, `i`, `c`, `q`, `y`,
`!`, `$`, BRE groups, the `I` flag and the nth-occurrence flag were all missing,
and `sed -i` *appended* to the file instead of replacing it. Every one of those
failed silently -- the line came back unchanged -- which is the same
wrong-answer-not-an-error shape that made the old awk hand an actor 562 bytes of
lscpu when it asked for a CPU count.

sed is in nearly as many attacker one-liners as awk, and `sed -i` in particular
is how they edit sshd_config, crontabs and rc files. A sed that quietly does
nothing makes us look like a box where their edits do not stick.

Scope is what appears in real one-liners: addresses (line, $, /re/, ranges,
step, +N), negation, blocks, labels and branches, the hold space, and the
s/y/d/p/P/q/Q/a/i/c/n/N/D/g/G/h/H/x/z/=/r/w commands. Files are read and written
through the caller's VFS, never the real filesystem.
"""

import re

__all__ = ["run_sed", "SedError"]


_L_ESCAPES = {"\\": "\\\\", "\a": "\\a", "\b": "\\b", "\f": "\\f",
              "\n": "\\n", "\r": "\\r", "\t": "\\t", "\v": "\\v"}


def _escape_l(text):
    """sed's `l` rendering: named escapes, then octal for anything else
    outside printable ASCII."""
    out = []
    for ch in text:
        if ch in _L_ESCAPES:
            out.append(_L_ESCAPES[ch])
        elif " " <= ch <= "~":
            out.append(ch)
        else:
            out.append("\\%03o" % (ord(ch) & 0xFF))
    return "".join(out)


class SedError(Exception):
    pass


# --------------------------------------------------------------------------
# Regex translation
# --------------------------------------------------------------------------
_CLASSES = {"alpha": "a-zA-Z", "digit": "0-9", "alnum": "a-zA-Z0-9",
            "upper": "A-Z", "lower": "a-z", "space": r" \t\n\r\f\v",
            "blank": r" \t", "xdigit": "0-9A-Fa-f",
            "punct": re.escape("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"),
            "print": r"\x20-\x7e", "graph": r"\x21-\x7e",
            "cntrl": r"\x00-\x1f\x7f"}


def _posix(pattern):
    return re.sub(r"\[:([a-z]+):\]",
                  lambda m: _CLASSES.get(m.group(1), m.group(0)), pattern)


def to_python_re(pattern, extended):
    """POSIX BRE/ERE -> Python. In BRE, \\( \\) \\{ \\} \\| \\+ \\? are the
    operators and the bare characters are literal; ERE is the other way up."""
    src = _posix(pattern)
    out = []
    i, n = 0, len(src)
    in_class = False
    while i < n:
        c = src[i]
        if in_class:
            out.append(c)
            if c == "]" and not out[-2:-1] == ["["]:
                in_class = False
            i += 1
            continue
        if c == "[":
            in_class = True
            out.append(c)
            i += 1
            if i < n and src[i] == "^":
                out.append(src[i])
                i += 1
            if i < n and src[i] == "]":          # a literal ] must come first
                out.append("\\]")
                i += 1
            continue
        if c == "\\" and i + 1 < n:
            nxt = src[i + 1]
            if not extended and nxt in "(){}|+?":
                out.append(nxt)                   # operator in BRE
                i += 2
                continue
            if extended and nxt in "(){}|+?":
                out.append("\\" + nxt)            # literal in ERE
                i += 2
                continue
            if nxt in "ntrfva":
                # `sed 'N;s/\n/-/'` joins two lines -- without this the \n was
                # escaped to a literal "n" and the join silently did nothing.
                out.append({"n": "\n", "t": "\t", "r": "\r", "f": "\f",
                            "v": "\v", "a": "\a"}[nxt])
                i += 2
                continue
            if nxt in "wWsSbBdD<>":
                out.append({"<": r"\b(?=\w)", ">": r"\b(?<=\w)"}.get(
                    nxt, "\\" + nxt))
                i += 2
                continue
            if nxt.isdigit():
                out.append("\\" + nxt)            # backreference
                i += 2
                continue
            out.append(re.escape(nxt))
            i += 2
            continue
        if not extended and c in "(){}|+?":
            out.append("\\" + c)                  # literal in BRE
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _compile(pattern, extended, flags=0):
    try:
        return re.compile(to_python_re(pattern, extended), flags)
    except re.error as exc:
        raise SedError("invalid regex: %s" % exc)


# --------------------------------------------------------------------------
# Script parsing
# --------------------------------------------------------------------------
class _Cmd:
    __slots__ = ("addr1", "addr2", "negate", "name", "args", "block",
                 "active", "done", "end_line")

    def __init__(self):
        self.addr1 = self.addr2 = None
        self.negate = False
        self.name = ""
        self.args = None
        self.block = None
        self.active = False
        self.done = False
        self.end_line = 0


class _ScriptParser:
    def __init__(self, text, extended):
        self.s = text
        self.i = 0
        self.ext = extended

    def eof(self):
        return self.i >= len(self.s)

    def skip_ws(self):
        while not self.eof() and self.s[self.i] in " \t\n;":
            self.i += 1

    def parse(self, depth=0):
        cmds = []
        while True:
            self.skip_ws()
            if self.eof():
                break
            if self.s[self.i] == "}":
                if depth:
                    return cmds
                raise SedError("unexpected `}'")
            if self.s[self.i] == "#":
                while not self.eof() and self.s[self.i] != "\n":
                    self.i += 1
                continue
            cmds.append(self.command(depth))
        return cmds

    def address(self):
        c = self.s[self.i]
        if c == "$":
            self.i += 1
            return ("last",)
        if c.isdigit():
            j = self.i
            while j < len(self.s) and self.s[j].isdigit():
                j += 1
            num = int(self.s[self.i:j])
            self.i = j
            if not self.eof() and self.s[self.i] == "~":
                self.i += 1
                k = self.i
                while k < len(self.s) and self.s[k].isdigit():
                    k += 1
                step = int(self.s[self.i:k] or 0)
                self.i = k
                return ("step", num, step)
            return ("line", num)
        if c == "/" or c == "\\":
            if c == "\\":
                self.i += 1
                delim = self.s[self.i]
            else:
                delim = "/"
            self.i += 1
            pat, esc = [], False
            while not self.eof():
                ch = self.s[self.i]
                if esc:
                    pat.append(ch if ch == delim else "\\" + ch)
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == delim:
                    break
                else:
                    pat.append(ch)
                self.i += 1
            if self.eof():
                raise SedError("unterminated address regex")
            self.i += 1
            flags = 0
            while not self.eof() and self.s[self.i] in "IM":
                flags |= re.I if self.s[self.i] == "I" else re.M
                self.i += 1
            return ("re", _compile("".join(pat), self.ext, flags))
        return None

    def command(self, depth):
        cmd = _Cmd()
        cmd.addr1 = self.address()
        if cmd.addr1 is not None:
            self.skip_spaces()
            if not self.eof() and self.s[self.i] == ",":
                self.i += 1
                self.skip_spaces()
                if not self.eof() and self.s[self.i] == "+":
                    self.i += 1
                    j = self.i
                    while j < len(self.s) and self.s[j].isdigit():
                        j += 1
                    cmd.addr2 = ("plus", int(self.s[self.i:j] or 0))
                    self.i = j
                else:
                    cmd.addr2 = self.address()
        self.skip_spaces()
        while not self.eof() and self.s[self.i] == "!":
            cmd.negate = not cmd.negate
            self.i += 1
            self.skip_spaces()
        if self.eof():
            raise SedError("missing command")
        ch = self.s[self.i]
        cmd.name = ch
        self.i += 1
        if ch == "{":
            cmd.block = self.parse(depth + 1)
            self.skip_ws()
            if self.eof() or self.s[self.i] != "}":
                raise SedError("unmatched `{'")
            self.i += 1
            return cmd
        if ch == "s":
            cmd.args = self.subst()
            return cmd
        if ch == "y":
            cmd.args = self.translit()
            return cmd
        if ch in "aic":
            cmd.args = self.text_arg()
            return cmd
        if ch in "btT:":
            cmd.args = self.label()
            return cmd
        if ch in "rRwW":
            cmd.args = self.filename()
            return cmd
        if ch in "qQ":
            self.skip_spaces()
            j = self.i
            while j < len(self.s) and self.s[j].isdigit():
                j += 1
            cmd.args = int(self.s[self.i:j]) if j > self.i else 0
            self.i = j
            return cmd
        if ch in "dDpPnNgGhHxz=lF":
            return cmd
        raise SedError("unknown command: `%s'" % ch)

    def skip_spaces(self):
        while not self.eof() and self.s[self.i] in " \t":
            self.i += 1

    def _delimited(self, delim):
        buf, esc = [], False
        while not self.eof():
            ch = self.s[self.i]
            if esc:
                buf.append("\\" + ch)
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == delim:
                self.i += 1
                return "".join(buf)
            elif ch == "\n":
                raise SedError("unterminated command")
            else:
                buf.append(ch)
            self.i += 1
        raise SedError("unterminated command")

    def subst(self):
        if self.eof():
            raise SedError("unterminated `s'")
        delim = self.s[self.i]
        self.i += 1
        pattern = self._delimited(delim)
        repl = self._delimited(delim)
        gflag = False
        nth = 0
        pflag = False
        rflags = 0
        wfile = None
        while not self.eof() and self.s[self.i] not in ";\n}":
            c = self.s[self.i]
            if c == "g":
                gflag = True
            elif c == "p":
                pflag = True
            elif c in "iI":
                rflags |= re.I
            elif c in "mM":
                rflags |= re.M
            elif c.isdigit():
                j = self.i
                while j < len(self.s) and self.s[j].isdigit():
                    j += 1
                nth = int(self.s[self.i:j])
                self.i = j - 1
            elif c == "w":
                self.i += 1
                self.skip_spaces()
                j = self.i
                while j < len(self.s) and self.s[j] != "\n":
                    j += 1
                wfile = self.s[self.i:j]
                self.i = j - 1
            elif c in " \t":
                pass
            else:
                raise SedError("unknown option to `s': %s" % c)
            self.i += 1
        # The delimiter is escaped inside the pattern; unescape it now.
        if delim != "/":
            pattern = pattern.replace("\\" + delim, delim)
            repl = repl.replace("\\" + delim, delim)
        return {"re": _compile(pattern, self.ext, rflags), "repl": repl,
                "g": gflag, "nth": nth, "p": pflag, "w": wfile}

    def translit(self):
        delim = self.s[self.i]
        self.i += 1
        src = self._delimited(delim)
        dst = self._delimited(delim)
        unesc = lambda t: (t.replace("\\n", "\n").replace("\\t", "\t")
                           .replace("\\\\", "\\").replace("\\" + delim, delim))
        src, dst = unesc(src), unesc(dst)
        if len(src) != len(dst):
            raise SedError("strings for `y' command are different lengths")
        return {"from": src, "to": dst}

    def text_arg(self):
        # Both `a text` and the classic `a\<newline>text` forms.
        self.skip_spaces()
        if not self.eof() and self.s[self.i] == "\\":
            self.i += 1
            if not self.eof() and self.s[self.i] == "\n":
                self.i += 1
        buf = []
        while not self.eof():
            ch = self.s[self.i]
            if ch == "\\" and self.i + 1 < len(self.s):
                buf.append(self.s[self.i + 1])
                self.i += 2
                continue
            if ch == "\n":
                break
            buf.append(ch)
            self.i += 1
        return "".join(buf)

    def label(self):
        self.skip_spaces()
        j = self.i
        while j < len(self.s) and self.s[j] not in ";\n}":
            j += 1
        name = self.s[self.i:j].strip()
        self.i = j
        return name

    def filename(self):
        self.skip_spaces()
        j = self.i
        while j < len(self.s) and self.s[j] != "\n":
            j += 1
        name = self.s[self.i:j].strip()
        self.i = j
        return name


# --------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------
class _Quit(Exception):
    def __init__(self, code=0, silent=False):
        Exception.__init__(self)
        self.code = code
        self.silent = silent


class _NextCycle(Exception):
    """`d`: drop the pattern space and start the next cycle."""


class _RestartCycle(Exception):
    """`D` with an embedded newline: restart without reading a new line."""


class _Branch(Exception):
    def __init__(self, label):
        Exception.__init__(self)
        self.label = label


class _Sed:
    def __init__(self, cmds, quiet, hooks, separate=False):
        self.cmds = cmds
        self.quiet = quiet
        self.hooks = hooks
        self.out = []
        self.hold = ""
        self.pattern = ""
        self.line_no = 0
        self.last = False
        self.append_q = []
        self.subst_made = False
        self.exit_code = 0
        self.labels = self._collect_labels(cmds)

    @staticmethod
    def _collect_labels(cmds):
        found = set()

        def walk(lst):
            for c in lst:
                if c.name == ":":
                    found.add(c.args)
                if c.block:
                    walk(c.block)
        walk(cmds)
        return found

    def emit(self, text):
        self.out.append(text)

    def _match_addr(self, addr):
        kind = addr[0]
        if kind == "line":
            return self.line_no == addr[1]
        if kind == "last":
            return self.last
        if kind == "re":
            return addr[1].search(self.pattern) is not None
        if kind == "step":
            first, step = addr[1], addr[2]
            if step <= 0:
                return self.line_no == first
            return self.line_no >= first and (self.line_no - first) % step == 0
        return False

    def _selected(self, cmd):
        if cmd.addr1 is None:
            sel = True
        elif cmd.addr2 is None:
            sel = self._match_addr(cmd.addr1)
        else:
            if not cmd.active:
                if self._match_addr(cmd.addr1):
                    cmd.active = True
                    # A numeric end address already passed means one line only.
                    if cmd.addr2[0] == "line" and cmd.addr2[1] <= self.line_no:
                        cmd.active = False
                    elif cmd.addr2[0] == "plus":
                        cmd.end_line = self.line_no + cmd.addr2[1]
                        if cmd.addr2[1] == 0:
                            cmd.active = False
                    sel = True
                else:
                    sel = False
            else:
                sel = True
                if cmd.addr2[0] == "plus":
                    if self.line_no >= getattr(cmd, "end_line", 0):
                        cmd.active = False
                elif self._match_addr(cmd.addr2):
                    cmd.active = False
        return sel != cmd.negate

    def _expand_repl(self, repl, m):
        out, i = [], 0
        case_one = None
        case_all = None

        def push(text):
            nonlocal case_one, case_all
            for ch in text:
                if case_one == "u":
                    ch = ch.upper()
                    case_one = None
                elif case_one == "l":
                    ch = ch.lower()
                    case_one = None
                elif case_all == "U":
                    ch = ch.upper()
                elif case_all == "L":
                    ch = ch.lower()
                out.append(ch)

        while i < len(repl):
            c = repl[i]
            if c == "\\" and i + 1 < len(repl):
                nxt = repl[i + 1]
                if nxt.isdigit():
                    try:
                        push(m.group(int(nxt)) or "")
                    except (IndexError, re.error):
                        pass
                    i += 2
                    continue
                if nxt in "UL":
                    case_all = nxt
                    i += 2
                    continue
                if nxt in "ul":
                    case_one = nxt
                    i += 2
                    continue
                if nxt == "E":
                    case_all = None
                    i += 2
                    continue
                push({"n": "\n", "t": "\t", "r": "\r", "\\": "\\",
                      "&": "&"}.get(nxt, nxt))
                i += 2
                continue
            if c == "&":
                push(m.group(0))
                i += 1
                continue
            push(c)
            i += 1
        return "".join(out)

    def _do_subst(self, spec):
        rx, repl = spec["re"], spec["repl"]
        nth = spec["nth"] or 1
        matches = list(rx.finditer(self.pattern))
        if len(matches) < nth:
            return False
        pieces, last_end, done = [], 0, 0
        for k, m in enumerate(matches, 1):
            if k < nth:
                continue
            if not spec["g"] and k > nth:
                break
            pieces.append(self.pattern[last_end:m.start()])
            pieces.append(self._expand_repl(repl, m))
            last_end = m.end()
            done += 1
            if m.start() == m.end():
                # A zero-width match must still advance, or `s/x*/-/g` loops.
                if last_end < len(self.pattern):
                    pieces.append(self.pattern[last_end])
                    last_end += 1
        if not done:
            return False
        pieces.append(self.pattern[last_end:])
        self.pattern = "".join(pieces)
        if spec["w"] and self.hooks is not None:
            self.hooks.write_file(spec["w"], self.pattern + "\n")
        if spec["p"]:
            self.emit(self.pattern + "\n")
        return True

    def _run_list(self, cmds, feed):
        for cmd in cmds:
            name = cmd.name
            if name == ":":
                continue
            if not self._selected(cmd):
                continue
            if name == "{":
                self._run_list(cmd.block, feed)
            elif name == "s":
                if self._do_subst(cmd.args):
                    self.subst_made = True
            elif name == "y":
                table = str.maketrans(cmd.args["from"], cmd.args["to"])
                self.pattern = self.pattern.translate(table)
            elif name == "d":
                raise _NextCycle()
            elif name == "D":
                if "\n" in self.pattern:
                    self.pattern = self.pattern.split("\n", 1)[1]
                    raise _RestartCycle()
                raise _NextCycle()
            elif name == "p":
                self.emit(self.pattern + "\n")
            elif name == "P":
                self.emit(self.pattern.split("\n", 1)[0] + "\n")
            elif name == "=":
                self.emit("%d\n" % self.line_no)
            elif name == "l":
                # `l` escapes what it prints: a tab is \t, other control and
                # high bytes are three-digit octal. Emitting the raw byte
                # meant `sed -n l` claimed a file held a literal tab where
                # a real sed writes \t -- and the whole point of `l` is to
                # make the invisible visible.
                self.emit(_escape_l(self.pattern) + "$\n")
            elif name == "a":
                self.append_q.append(cmd.args + "\n")
            elif name == "i":
                self.emit(cmd.args + "\n")
            elif name == "c":
                # For a range, the text is emitted once, at the end.
                if cmd.addr2 is None or not cmd.active:
                    self.emit(cmd.args + "\n")
                raise _NextCycle()
            elif name == "n":
                if not self.quiet:
                    self.emit(self.pattern + "\n")
                self._flush_appends()
                nxt = feed()
                if nxt is None:
                    raise _Quit(silent=True)
                self.pattern = nxt
            elif name == "N":
                nxt = feed()
                if nxt is None:
                    # GNU sed prints the pattern space and exits.
                    raise _Quit()
                self.pattern += "\n" + nxt
            elif name == "g":
                self.pattern = self.hold
            elif name == "G":
                self.pattern = self.pattern + "\n" + self.hold
            elif name == "h":
                self.hold = self.pattern
            elif name == "H":
                self.hold = self.hold + "\n" + self.pattern
            elif name == "x":
                self.pattern, self.hold = self.hold, self.pattern
            elif name == "z":
                self.pattern = ""
            elif name == "q":
                raise _Quit(cmd.args or 0)
            elif name == "Q":
                raise _Quit(cmd.args or 0, silent=True)
            elif name == "b":
                if not cmd.args:
                    raise _Branch(None)
                raise _Branch(cmd.args)
            elif name == "t":
                if self.subst_made:
                    self.subst_made = False
                    raise _Branch(cmd.args or None)
            elif name == "T":
                if not self.subst_made:
                    raise _Branch(cmd.args or None)
                self.subst_made = False
            elif name in ("r", "R"):
                if self.hooks is not None:
                    body = self.hooks.read_file(cmd.args)
                    if body:
                        self.append_q.append(body if body.endswith("\n")
                                             else body + "\n")
            elif name in ("w", "W"):
                if self.hooks is not None:
                    self.hooks.write_file(cmd.args, self.pattern + "\n")
            elif name == "F":
                self.emit("-\n")

    def _flush_appends(self):
        for text in self.append_q:
            self.emit(text)
        self.append_q = []

    def _find_label(self, label):
        """Flatten to a command list starting at `label`. Branching into a
        block is not supported; branching to a top-level label is."""
        flat = []
        seen = [False]

        def walk(lst):
            for c in lst:
                if seen[0]:
                    flat.append(c)
                elif c.name == ":" and c.args == label:
                    seen[0] = True
                elif c.block:
                    walk(c.block)
        walk(self.cmds)
        return flat if seen[0] else None

    def run(self, lines):
        total = len(lines)
        idx = [0]

        def feed():
            if idx[0] >= total:
                return None
            idx[0] += 1
            self.line_no = idx[0]
            self.last = idx[0] >= total
            return lines[idx[0] - 1]

        while True:
            nxt = feed()
            if nxt is None:
                break
            self.pattern = nxt
            self.subst_made = False
            restart = True
            while restart:
                restart = False
                todo = self.cmds
                hops = 0
                while True:
                    hops += 1
                    if hops > 1000:
                        self.exit_code = 4
                        return
                    try:
                        self._run_list(todo, feed)
                    except _Branch as br:
                        if br.label is None:
                            break
                        found = self._find_label(br.label)
                        if found is None:
                            self.exit_code = 1
                            return
                        todo = found
                        continue
                    except _NextCycle:
                        self._flush_appends()
                        break
                    except _RestartCycle:
                        restart = True
                        break
                    except _Quit as q:
                        if not q.silent and not self.quiet:
                            self.emit(self.pattern + "\n")
                        self._flush_appends()
                        self.exit_code = q.code
                        return
                    if not self.quiet:
                        self.emit(self.pattern + "\n")
                    self._flush_appends()
                    break


def run_sed(script, lines, quiet=False, extended=False, hooks=None):
    """(stdout, stderr, exit_code). A parse failure is an error, never a
    passthrough of the input."""
    try:
        cmds = _ScriptParser(script, extended).parse()
    except SedError as exc:
        return "", "sed: -e expression #1, char %d: %s\n" % (len(script), exc), 1
    except RecursionError:
        return "", "sed: script too deeply nested\n", 1
    machine = _Sed(cmds, quiet, hooks)
    try:
        machine.run(lines)
    except SedError as exc:
        return "".join(machine.out), "sed: %s\n" % exc, 1
    except RecursionError:
        return "".join(machine.out), "sed: script too deeply nested\n", 1
    return "".join(machine.out), "", machine.exit_code
