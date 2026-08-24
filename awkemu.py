"""A small but genuine awk, for the shell emulator.

Why this exists: the previous awk matched two shapes with a regex --
`/pat/ {print ...}` and `{print ...}` -- and *anything else fell through to
printing $0*. So a program it did not understand silently behaved like `cat`.
On 2026-08-20 19:35 an actor ran

    lscpu 2>/dev/null | awk -F: '/^CPU\\(s\\):/ {gsub(/ /,"",$2); print $2}'

expecting "4" and got all 562 bytes of lscpu, because `gsub` was unsupported.
That is the worst failure mode available: not an error the caller can detect,
but a confidently wrong answer. awk appears in almost every recon one-liner we
capture, so it is worth a real implementation.

Scope is deliberately "what appears in attacker one-liners": patterns and
actions, BEGIN/END, fields and field assignment, the usual operators, control
flow, arrays, and the string functions. Anything unparseable is a syntax error
on stderr with exit 2 -- what real awk does -- never a passthrough.

`system()` never executes anything; it reports failure and is logged by the
caller. `getline` from a command is refused for the same reason.
"""

import math
import re

__all__ = ["run_awk", "AwkSyntaxError"]


class AwkSyntaxError(Exception):
    pass


class _Exit(Exception):
    def __init__(self, code=0):
        Exception.__init__(self)
        self.code = code


class _Next(Exception):
    pass


# --------------------------------------------------------------------------
# Lexer
# --------------------------------------------------------------------------
_KEYWORDS = {"BEGIN", "END", "function", "func", "if", "else", "while", "for",
             "do", "break", "continue", "next", "nextfile", "exit", "return",
             "delete", "in", "getline", "print", "printf"}

_BUILTINS = {"length", "substr", "index", "split", "sub", "gsub", "match",
             "sprintf", "sin", "cos", "atan2", "exp", "log", "sqrt", "int",
             "rand", "srand", "tolower", "toupper", "system", "close",
             "fflush"}

# Longest first so ">>" is not read as ">" ">".
_OPS = ["**=", "...", ">>=", "<<=", "&&", "||", "==", "!=", "<=", ">=", "++",
        "--", "+=", "-=", "*=", "/=", "%=", "^=", "!~", ">>", "**",
        "{", "}", "(", ")", "[", "]", ";", ",", "+", "-", "*", "/", "%", "^",
        "<", ">", "=", "!", "?", ":", "~", "$", "|", "&"]

# A "/" begins a regex unless the previous token could end a value.
_VALUE_END = ("NAME", "NUMBER", "STRING", "ERE", "BUILTIN")


def _lex(src):
    toks = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c in " \t":
            i += 1
            continue
        if c == "\\" and i + 1 < n and src[i + 1] == "\n":
            i += 2
            continue
        if c == "\n":
            # A newline is a statement terminator, but not after these.
            if toks and (toks[-1][0] in ("OP",) and toks[-1][1] in
                         ("{", ";", "&&", "||", ",", "else", "do")):
                i += 1
                continue
            if toks and toks[-1][0] == "KEYWORD" and toks[-1][1] in ("else",
                                                                    "do"):
                i += 1
                continue
            toks.append(("NEWLINE", "\n"))
            i += 1
            continue
        if c == "#":
            while i < n and src[i] != "\n":
                i += 1
            continue
        if c == '"':
            j, buf = i + 1, []
            while j < n and src[j] != '"':
                if src[j] == "\\" and j + 1 < n:
                    esc = src[j + 1]
                    buf.append({"n": "\n", "t": "\t", "r": "\r", "\\": "\\",
                                '"': '"', "/": "/", "a": "\a", "b": "\b",
                                "f": "\f", "v": "\v"}.get(esc, "\\" + esc))
                    j += 2
                    continue
                buf.append(src[j])
                j += 1
            if j >= n:
                raise AwkSyntaxError("newline in string")
            toks.append(("STRING", "".join(buf)))
            i = j + 1
            continue
        if c.isdigit() or (c == "." and i + 1 < n and src[i + 1].isdigit()):
            m = re.match(r"(?:0[xX][0-9a-fA-F]+|\d+\.?\d*(?:[eE][-+]?\d+)?"
                         r"|\.\d+(?:[eE][-+]?\d+)?)", src[i:])
            toks.append(("NUMBER", m.group()))
            i += len(m.group())
            continue
        if c.isalpha() or c == "_":
            m = re.match(r"[A-Za-z_][A-Za-z_0-9]*", src[i:])
            word = m.group()
            i += len(word)
            if word in _KEYWORDS:
                toks.append(("KEYWORD", word))
            elif word in _BUILTINS:
                toks.append(("BUILTIN", word))
            else:
                toks.append(("NAME", word))
            continue
        if c == "/" and not (toks and toks[-1][0] in _VALUE_END) and \
                not (toks and toks[-1][0] == "OP" and toks[-1][1] in
                     (")", "]", "++", "--")):
            j, buf = i + 1, []
            while j < n and src[j] != "/":
                if src[j] == "\\" and j + 1 < n:
                    buf.append(src[j:j + 2])
                    j += 2
                    continue
                if src[j] == "\n":
                    raise AwkSyntaxError("newline in regex")
                buf.append(src[j])
                j += 1
            if j >= n:
                raise AwkSyntaxError("unterminated regex")
            toks.append(("ERE", "".join(buf)))
            i = j + 1
            continue
        for op in _OPS:
            if src.startswith(op, i):
                toks.append(("OP", op))
                i += len(op)
                break
        else:
            raise AwkSyntaxError("unexpected character %r" % c)
    toks.append(("EOF", ""))
    return toks


# --------------------------------------------------------------------------
# Parser -> tuple AST
# --------------------------------------------------------------------------
class _Parser:
    def __init__(self, toks):
        self.t = toks
        self.i = 0

    def peek(self, k=0):
        return self.t[min(self.i + k, len(self.t) - 1)]

    def at(self, kind, val=None):
        tk = self.peek()
        return tk[0] == kind and (val is None or tk[1] == val)

    def take(self, kind=None, val=None):
        tk = self.peek()
        if kind and (tk[0] != kind or (val is not None and tk[1] != val)):
            raise AwkSyntaxError("expected %s %s, got %r"
                                 % (kind, val or "", tk[1]))
        self.i += 1
        return tk

    def skip_terms(self):
        while self.at("NEWLINE") or self.at("OP", ";"):
            self.i += 1

    # -- program
    def program(self):
        items = []
        self.skip_terms()
        while not self.at("EOF"):
            items.append(self.item())
            self.skip_terms()
        return items

    def item(self):
        if self.at("KEYWORD", "BEGIN"):
            self.take()
            return ("BEGIN", self.block())
        if self.at("KEYWORD", "END"):
            self.take()
            return ("END", self.block())
        if self.at("KEYWORD", "function") or self.at("KEYWORD", "func"):
            self.take()
            name = self.take("NAME")[1]
            self.take("OP", "(")
            params = []
            while not self.at("OP", ")"):
                params.append(self.take("NAME")[1])
                if self.at("OP", ","):
                    self.take()
            self.take("OP", ")")
            self.skip_terms()
            return ("FUNC", name, params, self.block())
        if self.at("OP", "{"):
            return ("RULE", None, self.block())
        pat = self.expr()
        if self.at("OP", ","):                    # range pattern
            self.take()
            pat2 = self.expr()
            body = self.block() if self.at("OP", "{") else \
                ("BLOCK", [("PRINT", [])])
            return ("RANGE", pat, pat2, body, [False])
        body = self.block() if self.at("OP", "{") else \
            ("BLOCK", [("PRINT", [])])
        return ("RULE", pat, body)

    def block(self):
        self.take("OP", "{")
        stmts = []
        self.skip_terms()
        while not self.at("OP", "}"):
            if self.at("EOF"):
                raise AwkSyntaxError("unexpected end of program")
            stmts.append(self.statement())
            self.skip_terms()
        self.take("OP", "}")
        return ("BLOCK", stmts)

    def statement(self):
        if self.at("OP", "{"):
            return self.block()
        if self.at("KEYWORD", "if"):
            self.take()
            self.take("OP", "(")
            cond = self.expr()
            self.take("OP", ")")
            self.skip_terms()
            then = self.statement()
            save = self.i
            self.skip_terms()
            if self.at("KEYWORD", "else"):
                self.take()
                self.skip_terms()
                return ("IF", cond, then, self.statement())
            self.i = save
            return ("IF", cond, then, None)
        if self.at("KEYWORD", "while"):
            self.take()
            self.take("OP", "(")
            cond = self.expr()
            self.take("OP", ")")
            self.skip_terms()
            return ("WHILE", cond, self.statement())
        if self.at("KEYWORD", "do"):
            self.take()
            self.skip_terms()
            body = self.statement()
            self.skip_terms()
            self.take("KEYWORD", "while")
            self.take("OP", "(")
            cond = self.expr()
            self.take("OP", ")")
            return ("DO", body, cond)
        if self.at("KEYWORD", "for"):
            self.take()
            self.take("OP", "(")
            # for (k in arr)
            if self.at("NAME") and self.peek(1)[0] == "KEYWORD" \
                    and self.peek(1)[1] == "in":
                var = self.take("NAME")[1]
                self.take("KEYWORD", "in")
                arr = self.take("NAME")[1]
                self.take("OP", ")")
                self.skip_terms()
                return ("FORIN", var, arr, self.statement())
            init = None if self.at("OP", ";") else self.simple_statement()
            self.take("OP", ";")
            cond = None if self.at("OP", ";") else self.expr()
            self.take("OP", ";")
            step = None if self.at("OP", ")") else self.simple_statement()
            self.take("OP", ")")
            self.skip_terms()
            return ("FOR", init, cond, step, self.statement())
        if self.at("KEYWORD", "next") or self.at("KEYWORD", "nextfile"):
            self.take()
            return ("NEXT",)
        if self.at("KEYWORD", "break"):
            self.take()
            return ("BREAK",)
        if self.at("KEYWORD", "continue"):
            self.take()
            return ("CONTINUE",)
        if self.at("KEYWORD", "exit"):
            self.take()
            e = None if self._stmt_end() else self.expr()
            return ("EXIT", e)
        if self.at("KEYWORD", "return"):
            self.take()
            e = None if self._stmt_end() else self.expr()
            return ("RETURN", e)
        if self.at("KEYWORD", "delete"):
            self.take()
            name = self.take("NAME")[1]
            if self.at("OP", "["):
                self.take()
                idx = [self.expr()]
                while self.at("OP", ","):
                    self.take()
                    idx.append(self.expr())
                self.take("OP", "]")
                return ("DELETE", name, idx)
            return ("DELETE", name, None)
        return self.simple_statement()

    def _stmt_end(self):
        return self.at("NEWLINE") or self.at("OP", ";") or self.at("OP", "}") \
            or self.at("EOF")

    def simple_statement(self):
        if self.at("KEYWORD", "print") or self.at("KEYWORD", "printf"):
            kind = self.take()[1]
            args = []
            if not self._stmt_end() and not self.at("OP", ">") \
                    and not self.at("OP", "|"):
                args.append(self.expr(no_gt=True))
                while self.at("OP", ","):
                    self.take()
                    self.skip_terms()
                    args.append(self.expr(no_gt=True))
            redirect = None
            if self.at("OP", ">") or self.at("OP", ">>") or self.at("OP", "|"):
                op = self.take()[1]
                redirect = (op, self.expr(no_gt=True))
            # `print (a, b)` parses as one grouping; flatten it.
            if len(args) == 1 and isinstance(args[0], tuple) \
                    and args[0][0] == "GROUP_LIST":
                args = list(args[0][1])
            return ("PRINTF" if kind == "printf" else "PRINT", args, redirect)
        return ("EXPR", self.expr())

    # -- expressions, lowest precedence first
    def expr(self, no_gt=False):
        return self.ternary(no_gt)

    def ternary(self, no_gt=False):
        cond = self.or_(no_gt)
        if self.at("OP", "?"):
            self.take()
            a = self.ternary(no_gt)
            self.take("OP", ":")
            b = self.ternary(no_gt)
            return ("COND", cond, a, b)
        # assignment is right-associative and lower than ternary in practice
        if self.at("OP", "=") and self._is_lvalue(cond):
            self.take()
            return ("ASSIGN", "=", cond, self.ternary(no_gt))
        for op in ("+=", "-=", "*=", "/=", "%=", "^="):
            if self.at("OP", op) and self._is_lvalue(cond):
                self.take()
                return ("ASSIGN", op, cond, self.ternary(no_gt))
        return cond

    @staticmethod
    def _is_lvalue(node):
        return isinstance(node, tuple) and node[0] in ("VAR", "FIELD", "INDEX")

    def or_(self, no_gt=False):
        left = self.and_(no_gt)
        while self.at("OP", "||"):
            self.take()
            self.skip_terms()
            left = ("OR", left, self.and_(no_gt))
        return left

    def and_(self, no_gt=False):
        left = self.in_(no_gt)
        while self.at("OP", "&&"):
            self.take()
            self.skip_terms()
            left = ("AND", left, self.in_(no_gt))
        return left

    def in_(self, no_gt=False):
        left = self.match_(no_gt)
        while self.at("KEYWORD", "in"):
            self.take()
            left = ("IN", left, self.take("NAME")[1])
        return left

    def match_(self, no_gt=False):
        left = self.compare(no_gt)
        while self.at("OP", "~") or self.at("OP", "!~"):
            op = self.take()[1]
            left = ("MATCH", op == "~", left, self.compare(no_gt))
        return left

    _CMP = ("<", "<=", ">", ">=", "!=", "==")

    def compare(self, no_gt=False):
        left = self.concat(no_gt)
        tk = self.peek()
        if tk[0] == "OP" and tk[1] in self._CMP:
            if tk[1] == ">" and no_gt:
                return left
            self.take()
            return ("CMP", tk[1], left, self.concat(no_gt))
        return left

    _CONCAT_STOP = {")", "]", "}", ";", ",", "?", ":", "=", "|",
                    "&&", "||", "~", "!~", ">", ">=", "<", "<=", "==", "!=",
                    ">>", "+=", "-=", "*=", "/=", "%=", "^="}

    def concat(self, no_gt=False):
        left = self.additive(no_gt)
        while True:
            tk = self.peek()
            if tk[0] in ("NUMBER", "STRING", "NAME", "ERE", "BUILTIN"):
                left = ("CONCAT", left, self.additive(no_gt))
                continue
            if tk[0] == "OP" and tk[1] in ("$", "(", "!", "++", "--"):
                left = ("CONCAT", left, self.additive(no_gt))
                continue
            return left

    def additive(self, no_gt=False):
        left = self.multiplicative(no_gt)
        while self.at("OP", "+") or self.at("OP", "-"):
            op = self.take()[1]
            left = ("BIN", op, left, self.multiplicative(no_gt))
        return left

    def multiplicative(self, no_gt=False):
        left = self.unary(no_gt)
        while self.at("OP", "*") or self.at("OP", "/") or self.at("OP", "%"):
            op = self.take()[1]
            left = ("BIN", op, left, self.unary(no_gt))
        return left

    def unary(self, no_gt=False):
        if self.at("OP", "!"):
            self.take()
            return ("NOT", self.unary(no_gt))
        if self.at("OP", "-"):
            self.take()
            return ("NEG", self.unary(no_gt))
        if self.at("OP", "+"):
            self.take()
            return ("POS", self.unary(no_gt))
        return self.power(no_gt)

    def power(self, no_gt=False):
        base = self.postfix(no_gt)
        if self.at("OP", "^") or self.at("OP", "**"):
            self.take()
            return ("BIN", "^", base, self.unary(no_gt))
        return base

    def postfix(self, no_gt=False):
        if self.at("OP", "++") or self.at("OP", "--"):
            op = self.take()[1]
            target = self.postfix(no_gt)
            return ("PREINC", op, target)
        node = self.primary(no_gt)
        while self.at("OP", "++") or self.at("OP", "--"):
            if not self._is_lvalue(node):
                break
            op = self.take()[1]
            node = ("POSTINC", op, node)
        return node

    def primary(self, no_gt=False):
        tk = self.peek()
        if tk[0] == "NUMBER":
            self.take()
            txt = tk[1]
            val = float(int(txt, 16)) if txt[:2].lower() == "0x" else float(txt)
            return ("NUM", val)
        if tk[0] == "STRING":
            self.take()
            return ("STR", tk[1])
        if tk[0] == "ERE":
            self.take()
            return ("REGEX", tk[1])
        if tk[0] == "OP" and tk[1] == "$":
            self.take()
            return ("FIELD", self.primary(no_gt))
        if tk[0] == "OP" and tk[1] == "(":
            self.take()
            first = self.expr()
            if self.at("OP", ","):
                items = [first]
                while self.at("OP", ","):
                    self.take()
                    items.append(self.expr())
                self.take("OP", ")")
                if self.at("KEYWORD", "in"):
                    self.take()
                    return ("IN", ("GROUP_LIST", items), self.take("NAME")[1])
                return ("GROUP_LIST", items)
            self.take("OP", ")")
            return first
        if tk[0] == "BUILTIN":
            self.take()
            args = []
            if self.at("OP", "("):
                self.take()
                while not self.at("OP", ")"):
                    args.append(self.expr())
                    if self.at("OP", ","):
                        self.take()
                self.take("OP", ")")
            return ("CALL", tk[1], args)
        if tk[0] == "NAME":
            self.take()
            if self.at("OP", "["):
                self.take()
                idx = [self.expr()]
                while self.at("OP", ","):
                    self.take()
                    idx.append(self.expr())
                self.take("OP", "]")
                return ("INDEX", tk[1], idx)
            if self.at("OP", "(") and self.peek(-1)[1] == tk[1]:
                self.take()
                args = []
                while not self.at("OP", ")"):
                    args.append(self.expr())
                    if self.at("OP", ","):
                        self.take()
                self.take("OP", ")")
                return ("USERCALL", tk[1], args)
            return ("VAR", tk[1])
        if tk[0] == "KEYWORD" and tk[1] == "getline":
            raise AwkSyntaxError("getline is not supported")
        raise AwkSyntaxError("unexpected %r" % (tk[1],))


# --------------------------------------------------------------------------
# Values
# --------------------------------------------------------------------------
_NUM_RE = re.compile(r"^[ \t]*[-+]?(?:\d+\.?\d*(?:[eE][-+]?\d+)?"
                     r"|\.\d+(?:[eE][-+]?\d+)?|nan|inf(?:inity)?)[ \t]*$",
                     re.I)


def _to_num(v):
    if isinstance(v, float):
        return v
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if v is None:
        return 0.0
    txt = str(v)
    m = re.match(r"[ \t]*[-+]?(?:\d+\.?\d*(?:[eE][-+]?\d+)?|\.\d+(?:[eE][-+]?\d+)?)",
                 txt)
    if not m or not m.group().strip():
        return 0.0
    try:
        return float(m.group())
    except ValueError:
        return 0.0


def _num_str(x):
    """How awk renders a number: integers bare, otherwise CONVFMT (%.6g)."""
    if x != x or x in (float("inf"), float("-inf")):
        return {float("inf"): "inf", float("-inf"): "-inf"}.get(x, "nan")
    if x == int(x) and abs(x) < 1e16:
        return str(int(x))
    return "%.6g" % x


def _to_str(v):
    if isinstance(v, float):
        return _num_str(v)
    if v is None:
        return ""
    return str(v)


def _truthy(v):
    # A field or input string is true if it is non-empty; a number if non-zero.
    if isinstance(v, float):
        return v != 0.0
    if v is None:
        return False
    if isinstance(v, _StrNum):
        return _to_num(v) != 0.0 if _NUM_RE.match(str(v)) else str(v) != ""
    return str(v) != ""


class _StrNum(str):
    """A string that came from input, so it compares numerically when it looks
    like a number. This is what makes `$1 == 0` true for a field of "0.0"."""


def _looks_num(v):
    return isinstance(v, float) or (isinstance(v, _StrNum)
                                    and bool(_NUM_RE.match(str(v))))


def _compare(a, b):
    if _looks_num(a) and _looks_num(b):
        x, y = _to_num(a), _to_num(b)
        return -1 if x < y else (1 if x > y else 0)
    x, y = _to_str(a), _to_str(b)
    return -1 if x < y else (1 if x > y else 0)


def _ere(pattern):
    return re.compile(_posix_ere(pattern))


_CLASSES = {"alpha": "a-zA-Z", "digit": "0-9", "alnum": "a-zA-Z0-9",
            "upper": "A-Z", "lower": "a-z", "space": r" \t\n\r\f\v",
            "blank": r" \t", "punct": re.escape("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"),
            "print": r"\x20-\x7e", "graph": r"\x21-\x7e",
            "cntrl": r"\x00-\x1f\x7f", "xdigit": "0-9A-Fa-f"}


def _posix_ere(pattern):
    out = re.sub(r"\[:([a-z]+):\]",
                 lambda m: _CLASSES.get(m.group(1), m.group(0)), pattern)
    # awk EREs have no non-greedy or lookaround; braces are literal when they
    # are not a valid interval.
    return out


# --------------------------------------------------------------------------
# Interpreter
# --------------------------------------------------------------------------
class _Break(Exception):
    pass


class _Continue(Exception):
    pass


class _Return(Exception):
    def __init__(self, value):
        Exception.__init__(self)
        self.value = value


class Interp:
    def __init__(self, program, argv_fs=None, hooks=None, assigns=None):
        self.items = program
        self.out = []
        self.err = []
        self.hooks = hooks
        self.funcs = {i[1]: i for i in program if i[0] == "FUNC"}
        self.globals = {
            "FS": argv_fs if argv_fs is not None else " ",
            "OFS": " ", "ORS": "\n", "RS": "\n", "NR": 0.0, "NF": 0.0,
            "FNR": 0.0, "SUBSEP": "\x1c", "CONVFMT": "%.6g", "OFMT": "%.6g",
            "RSTART": 0.0, "RLENGTH": -1.0, "FILENAME": "",
        }
        for k, v in (assigns or {}).items():
            self.globals[k] = _StrNum(v)
        self.arrays = {}
        self.locals = []
        self.fields = [""]
        self.exit_code = 0

    # -- field handling
    def set_record(self, line):
        self.fields = [line]
        fs = _to_str(self.globals.get("FS", " "))
        if fs == " ":
            parts = line.split()
        elif len(fs) == 1 and fs not in ".[]()*+?^$|\\{}":
            parts = line.split(fs) if line else []
        elif len(fs) == 1:
            parts = line.split(fs) if line else []
        else:
            parts = re.split(_posix_ere(fs), line) if line else []
        self.fields.extend(parts)
        self.globals["NF"] = float(len(parts))

    def rebuild_record(self):
        ofs = _to_str(self.globals.get("OFS", " "))
        n = int(_to_num(self.globals.get("NF", 0)))
        vals = [_to_str(self.get_field(i)) for i in range(1, n + 1)]
        self.fields[0] = ofs.join(vals)

    def get_field(self, i):
        if i == 0:
            return _StrNum(self.fields[0])
        if 1 <= i < len(self.fields):
            return _StrNum(self.fields[i])
        return _StrNum("")

    def set_field(self, i, value):
        if i == 0:
            self.set_record(_to_str(value))
            return
        while len(self.fields) <= i:
            self.fields.append("")
        self.fields[i] = _to_str(value)
        if i > int(_to_num(self.globals.get("NF", 0))):
            self.globals["NF"] = float(i)
        self.rebuild_record()

    # -- variable scope
    def scope(self):
        return self.locals[-1] if self.locals else None

    def get_var(self, name):
        sc = self.scope()
        if sc is not None and name in sc:
            return sc[name]
        if name == "NF":
            return self.globals["NF"]
        return self.globals.get(name, _StrNum(""))

    def set_var(self, name, value):
        sc = self.scope()
        if sc is not None and name in sc:
            sc[name] = value
            return
        self.globals[name] = value
        if name == "NF":
            n = int(_to_num(value))
            while len(self.fields) - 1 < n:
                self.fields.append("")
            del self.fields[n + 1:]
            self.rebuild_record()

    def array(self, name):
        sc = self.scope()
        if sc is not None and name in sc and isinstance(sc[name], dict):
            return sc[name]
        return self.arrays.setdefault(name, {})

    # -- driver
    def run(self, records):
        try:
            for it in self.items:
                if it[0] == "BEGIN":
                    self.exec_stmt(it[1])
            for line in records:
                self.globals["NR"] = _to_num(self.globals["NR"]) + 1
                self.globals["FNR"] = _to_num(self.globals["FNR"]) + 1
                self.set_record(line)
                try:
                    for it in self.items:
                        if it[0] == "RULE":
                            if it[1] is None or _truthy(self.eval(it[1])):
                                self.exec_stmt(it[2])
                        elif it[0] == "RANGE":
                            active = it[4]
                            if not active[0]:
                                if _truthy(self.eval(it[1])):
                                    active[0] = True
                                    if _truthy(self.eval(it[2])):
                                        active[0] = False
                                    self.exec_stmt(it[3])
                            else:
                                if _truthy(self.eval(it[2])):
                                    active[0] = False
                                self.exec_stmt(it[3])
                except _Next:
                    continue
        except _Exit as exc:
            self.exit_code = exc.code
            try:
                for it in self.items:
                    if it[0] == "END":
                        self.exec_stmt(it[1])
            except _Exit as exc2:
                self.exit_code = exc2.code
            return
        try:
            for it in self.items:
                if it[0] == "END":
                    self.exec_stmt(it[1])
        except _Exit as exc:
            self.exit_code = exc.code

    # -- statements
    def exec_stmt(self, st):
        kind = st[0]
        if kind == "BLOCK":
            for s in st[1]:
                self.exec_stmt(s)
        elif kind == "PRINT":
            args = st[1]
            if not args:
                text = _to_str(self.get_field(0))
            else:
                ofs = _to_str(self.globals.get("OFS", " "))
                text = ofs.join(self._out_str(self.eval(a)) for a in args)
            self._emit(text + _to_str(self.globals.get("ORS", "\n")),
                       st[2] if len(st) > 2 else None)
        elif kind == "PRINTF":
            args = [self.eval(a) for a in st[1]]
            if not args:
                raise AwkSyntaxError("printf: no format")
            self._emit(_awk_sprintf(_to_str(args[0]), args[1:]),
                       st[2] if len(st) > 2 else None)
        elif kind == "EXPR":
            self.eval(st[1])
        elif kind == "IF":
            if _truthy(self.eval(st[1])):
                self.exec_stmt(st[2])
            elif st[3] is not None:
                self.exec_stmt(st[3])
        elif kind == "WHILE":
            while _truthy(self.eval(st[1])):
                try:
                    self.exec_stmt(st[2])
                except _Break:
                    break
                except _Continue:
                    continue
        elif kind == "DO":
            while True:
                try:
                    self.exec_stmt(st[1])
                except _Break:
                    break
                except _Continue:
                    pass
                if not _truthy(self.eval(st[2])):
                    break
        elif kind == "FOR":
            if st[1] is not None:
                self.exec_stmt(st[1])
            guard = 0
            while st[2] is None or _truthy(self.eval(st[2])):
                guard += 1
                if guard > 2000000:            # a runaway loop is a DoS on us
                    raise _Exit(2)
                try:
                    self.exec_stmt(st[4])
                except _Break:
                    break
                except _Continue:
                    pass
                if st[3] is not None:
                    self.exec_stmt(st[3])
        elif kind == "FORIN":
            for key in list(self.array(st[2])):
                self.set_var(st[1], _StrNum(key))
                try:
                    self.exec_stmt(st[3])
                except _Break:
                    break
                except _Continue:
                    continue
        elif kind == "NEXT":
            raise _Next()
        elif kind == "BREAK":
            raise _Break()
        elif kind == "CONTINUE":
            raise _Continue()
        elif kind == "EXIT":
            raise _Exit(int(_to_num(self.eval(st[1]))) if st[1] else 0)
        elif kind == "RETURN":
            raise _Return(self.eval(st[1]) if st[1] else _StrNum(""))
        elif kind == "DELETE":
            arr = self.array(st[1])
            if st[2] is None:
                arr.clear()
            else:
                arr.pop(self._subscript(st[2]), None)
        else:
            raise AwkSyntaxError("unhandled statement %r" % (kind,))

    def _out_str(self, v):
        if isinstance(v, float) and v != int(v):
            return _to_str(v)
        return _to_str(v)

    def _emit(self, text, redirect):
        if redirect is None:
            self.out.append(text)
            return
        op, target = redirect
        name = _to_str(self.eval(target))
        if op == "|":
            # Piping to a command would mean running it. Never.
            if self.hooks is not None:
                self.hooks.pipe_blocked(name, text)
            return
        if self.hooks is not None:
            self.hooks.write_file(name, text, append=(op == ">>"))
            return
        self.out.append(text)

    def _subscript(self, idx_nodes):
        sep = _to_str(self.globals.get("SUBSEP", "\x1c"))
        return sep.join(_to_str(self.eval(i)) for i in idx_nodes)

    # -- expressions
    def eval(self, node):
        kind = node[0]
        if kind == "NUM":
            return node[1]
        if kind == "STR":
            return node[1]
        if kind == "REGEX":
            # A bare regex in a value context matches $0.
            return 1.0 if _ere(node[1]).search(_to_str(self.get_field(0))) \
                else 0.0
        if kind == "VAR":
            return self.get_var(node[1])
        if kind == "FIELD":
            return self.get_field(int(_to_num(self.eval(node[1]))))
        if kind == "INDEX":
            arr = self.array(node[1])
            key = self._subscript(node[2])
            return arr.setdefault(key, _StrNum(""))
        if kind == "GROUP_LIST":
            return self.eval(node[1][-1]) if node[1] else _StrNum("")
        if kind == "CONCAT":
            return _to_str(self.eval(node[1])) + _to_str(self.eval(node[2]))
        if kind == "BIN":
            op = node[1]
            a, b = _to_num(self.eval(node[2])), _to_num(self.eval(node[3]))
            if op == "+":
                return a + b
            if op == "-":
                return a - b
            if op == "*":
                return a * b
            if op == "/":
                if b == 0:
                    raise _AwkRuntime("division by zero")
                return a / b
            if op == "%":
                if b == 0:
                    raise _AwkRuntime("division by zero in %")
                return math.fmod(a, b)
            if op == "^":
                if abs(b) > 1024:
                    return float("inf")
                try:
                    return float(a) ** float(b)
                except (OverflowError, ValueError):
                    return float("inf")
        if kind == "CMP":
            c = _compare(self.eval(node[2]), self.eval(node[3]))
            return 1.0 if {"<": c < 0, "<=": c <= 0, ">": c > 0,
                           ">=": c >= 0, "==": c == 0, "!=": c != 0}[node[1]] \
                else 0.0
        if kind == "MATCH":
            text = _to_str(self.eval(node[2]))
            pat = node[3]
            rx = _ere(pat[1]) if pat[0] == "REGEX" \
                else _ere(_to_str(self.eval(pat)))
            hit = rx.search(text) is not None
            return 1.0 if hit == node[1] else 0.0
        if kind == "AND":
            return 1.0 if (_truthy(self.eval(node[1]))
                           and _truthy(self.eval(node[2]))) else 0.0
        if kind == "OR":
            return 1.0 if (_truthy(self.eval(node[1]))
                           or _truthy(self.eval(node[2]))) else 0.0
        if kind == "NOT":
            return 0.0 if _truthy(self.eval(node[1])) else 1.0
        if kind == "NEG":
            return -_to_num(self.eval(node[1]))
        if kind == "POS":
            return _to_num(self.eval(node[1]))
        if kind == "COND":
            return self.eval(node[2]) if _truthy(self.eval(node[1])) \
                else self.eval(node[3])
        if kind == "IN":
            key = node[1]
            if key[0] == "GROUP_LIST":
                k = self._subscript(key[1])
            else:
                k = _to_str(self.eval(key))
            return 1.0 if k in self.array(node[2]) else 0.0
        if kind == "ASSIGN":
            return self._assign(node[1], node[2], node[3])
        if kind == "PREINC":
            cur = _to_num(self._lvalue_get(node[2]))
            new = cur + (1 if node[1] == "++" else -1)
            self._lvalue_set(node[2], new)
            return new
        if kind == "POSTINC":
            cur = _to_num(self._lvalue_get(node[2]))
            self._lvalue_set(node[2], cur + (1 if node[1] == "++" else -1))
            return cur
        if kind == "CALL":
            return self._builtin(node[1], node[2])
        if kind == "USERCALL":
            return self._usercall(node[1], node[2])
        raise AwkSyntaxError("unhandled expression %r" % (kind,))

    def _lvalue_get(self, node):
        if node[0] == "VAR":
            return self.get_var(node[1])
        if node[0] == "FIELD":
            return self.get_field(int(_to_num(self.eval(node[1]))))
        if node[0] == "INDEX":
            return self.array(node[1]).get(self._subscript(node[2]),
                                           _StrNum(""))
        raise AwkSyntaxError("not an lvalue")

    def _lvalue_set(self, node, value):
        if node[0] == "VAR":
            self.set_var(node[1], value)
            return
        if node[0] == "FIELD":
            self.set_field(int(_to_num(self.eval(node[1]))), value)
            return
        if node[0] == "INDEX":
            self.array(node[1])[self._subscript(node[2])] = value
            return
        raise AwkSyntaxError("not an lvalue")

    def _assign(self, op, target, expr):
        val = self.eval(expr)
        if op != "=":
            cur = _to_num(self._lvalue_get(target))
            rhs = _to_num(val)
            val = {"+=": cur + rhs, "-=": cur - rhs, "*=": cur * rhs,
                   "/=": cur / rhs if rhs else float("inf"),
                   "%=": math.fmod(cur, rhs) if rhs else 0.0,
                   "^=": cur ** rhs if abs(rhs) < 1024 else float("inf")}[op]
        self._lvalue_set(target, val)
        return val

    def _usercall(self, name, args):
        fn = self.funcs.get(name)
        if fn is None:
            raise _AwkRuntime("calling undefined function %s" % name)
        scope = {}
        for i, p in enumerate(fn[2]):
            if i < len(args):
                a = args[i]
                if a[0] == "VAR" and a[1] in self.arrays:
                    scope[p] = self.arrays[a[1]]
                    continue
                scope[p] = self.eval(a)
            else:
                scope[p] = _StrNum("")
        self.locals.append(scope)
        try:
            self.exec_stmt(fn[3])
            return _StrNum("")
        except _Return as r:
            return r.value
        finally:
            self.locals.pop()

    # -- built-in functions
    def _builtin(self, name, args):
        ev = lambda i: self.eval(args[i])
        if name == "length":
            if not args:
                return float(len(_to_str(self.get_field(0))))
            a = args[0]
            if a[0] == "VAR" and a[1] in self.arrays:
                return float(len(self.arrays[a[1]]))
            return float(len(_to_str(ev(0))))
        if name == "substr":
            # mawk's exact rule, mapped out against the real thing rather than
            # assumed: the start truncates toward zero (2.6 -> 2, not 3), and a
            # start below 1 clamps to 1 while *lengthening* the result by the
            # shortfall -- substr("abcdef", -2, 3) is "abcde", five characters
            # from a request for three.
            src = _to_str(ev(0))
            start = int(_to_num(ev(1)))
            lo = max(1, start)
            if len(args) > 2:
                ln = int(_to_num(ev(2))) - min(0, start)
                if ln <= 0:
                    return ""
                return src[lo - 1:lo - 1 + ln]
            return src[lo - 1:]
        if name == "index":
            return float(_to_str(ev(0)).find(_to_str(ev(1))) + 1)
        if name == "toupper":
            return _to_str(ev(0)).upper()
        if name == "tolower":
            return _to_str(ev(0)).lower()
        if name == "sprintf":
            return _awk_sprintf(_to_str(ev(0)),
                                [self.eval(a) for a in args[1:]])
        if name == "int":
            n = _to_num(ev(0))
            return float(int(n))
        if name in ("sin", "cos", "exp", "log", "sqrt"):
            n = _to_num(ev(0))
            try:
                return float({"sin": math.sin, "cos": math.cos,
                              "exp": math.exp, "log": math.log,
                              "sqrt": math.sqrt}[name](n))
            except (ValueError, OverflowError):
                return float("nan") if name in ("log", "sqrt") else float("inf")
        if name == "atan2":
            return math.atan2(_to_num(ev(0)), _to_num(ev(1)))
        if name == "rand":
            import random as _r
            return _r.random()
        if name == "srand":
            import random as _r
            prev = getattr(self, "_seed", 0.0)
            seed = _to_num(ev(0)) if args else 0.0
            self._seed = seed
            _r.seed(seed)
            return prev
        if name == "match":
            text = _to_str(ev(0))
            pat = args[1]
            rx = _ere(pat[1]) if pat[0] == "REGEX" else _ere(_to_str(ev(1)))
            m = rx.search(text)
            if m:
                self.globals["RSTART"] = float(m.start() + 1)
                self.globals["RLENGTH"] = float(m.end() - m.start())
                return float(m.start() + 1)
            self.globals["RSTART"] = 0.0
            self.globals["RLENGTH"] = -1.0
            return 0.0
        if name == "split":
            text = _to_str(ev(0))
            arr_node = args[1]
            if arr_node[0] != "VAR":
                raise _AwkRuntime("split: second argument must be an array")
            arr = self.array(arr_node[1])
            arr.clear()
            if len(args) > 2:
                pat = args[2]
                fs = pat[1] if pat[0] == "REGEX" else _to_str(ev(2))
            else:
                fs = _to_str(self.globals.get("FS", " "))
            if fs == " ":
                parts = text.split()
            elif len(fs) == 1:
                parts = text.split(fs) if text else []
            else:
                parts = re.split(_posix_ere(fs), text) if text else []
            for i, part in enumerate(parts, 1):
                arr[str(i)] = _StrNum(part)
            return float(len(parts))
        if name in ("sub", "gsub"):
            pat = args[0]
            rx = _ere(pat[1]) if pat[0] == "REGEX" else _ere(_to_str(ev(0)))
            repl = _to_str(ev(1))
            target = args[2] if len(args) > 2 else ("FIELD", ("NUM", 0.0))
            src = _to_str(self._lvalue_get(target))

            def _expand(m):
                # & is the matched text; \& is a literal ampersand.
                out, i = [], 0
                while i < len(repl):
                    if repl[i] == "\\" and i + 1 < len(repl):
                        if repl[i + 1] == "&":
                            out.append("&")
                            i += 2
                            continue
                        if repl[i + 1] == "\\":
                            out.append("\\")
                            i += 2
                            continue
                        out.append(repl[i + 1])
                        i += 2
                        continue
                    if repl[i] == "&":
                        out.append(m.group())
                        i += 1
                        continue
                    out.append(repl[i])
                    i += 1
                return "".join(out)

            count = 1 if name == "sub" else 0
            new, n = rx.subn(_expand, src, count=count)
            if n:
                self._lvalue_set(target, new)
            return float(n)
        if name == "system":
            cmd = _to_str(ev(0)) if args else ""
            # Executing this is the one thing a honeypot must never do.
            if self.hooks is not None:
                self.hooks.system_blocked(cmd)
            return 0.0
        if name in ("close", "fflush"):
            return 0.0
        raise _AwkRuntime("unknown function %s" % name)


class _AwkRuntime(Exception):
    pass


def _awk_sprintf(fmt, args):
    """awk's printf. Field widths are clamped: "%9999999d" is an allocation
    directive, and this runs on input we did not write."""
    fmt = re.sub(r"%([-+ #0]*)(\d{6,})", lambda m: "%%%s%d" % (m.group(1),
                                                               99999), fmt)
    spec = re.compile(r"%([-+ #0']*)(\*|\d*)(?:\.(\*|\d+))?"
                      r"([diouxXeEfFgGaAcs%])")
    out, pos, pool = [], 0, list(args)

    def nxt():
        return pool.pop(0) if pool else _StrNum("")

    while True:
        m = spec.search(fmt, pos)
        if not m:
            out.append(_unescape(fmt[pos:]))
            break
        out.append(_unescape(fmt[pos:m.start()]))
        flags, width, prec, conv = m.groups()
        if width == "*":
            width = str(int(_to_num(nxt())))
        if prec == "*":
            prec = str(int(_to_num(nxt())))
        if conv == "%":
            out.append("%")
            pos = m.end()
            continue
        val = nxt()
        try:
            if conv in "di":
                txt = "%d" % int(_to_num(val))
            elif conv in "ouxX":
                iv = int(_to_num(val))
                txt = ("%" + conv) % (iv & 0xFFFFFFFFFFFFFFFF if iv < 0 else iv)
            elif conv in "eEfFgGaA":
                p = int(prec) if prec not in (None, "") else 6
                txt = ("%." + str(p) + conv) % _to_num(val)
            elif conv == "c":
                if isinstance(val, float):
                    txt = chr(int(val) & 0xFF)
                else:
                    sv = _to_str(val)
                    txt = sv[0] if sv else ""
            else:
                txt = _to_str(val)
                if prec not in (None, ""):
                    txt = txt[:int(prec)]
        except (ValueError, OverflowError):
            txt = "0"
        if "+" in flags and conv in "diouxXeEfFgG" and not txt.startswith("-"):
            txt = "+" + txt
        if width:
            w = int(width)
            if "-" in flags:
                txt = txt.ljust(w)
            elif "0" in flags and conv != "s":
                sign = ""
                if txt[:1] in "+-":
                    sign, txt = txt[0], txt[1:]
                txt = sign + txt.rjust(w - len(sign), "0")
            else:
                txt = txt.rjust(w)
        out.append(txt)
        pos = m.end()
    return "".join(out)


def _unescape(text):
    out, i = [], 0
    while i < len(text):
        if text[i] == "\\" and i + 1 < len(text):
            c = text[i + 1]
            simple = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"',
                      "a": "\a", "b": "\b", "f": "\f", "v": "\v", "/": "/"}
            if c in simple:
                out.append(simple[c])
                i += 2
                continue
            m = re.match(r"[0-7]{1,3}", text[i + 1:])
            if m:
                out.append(chr(int(m.group(), 8) & 0xFF))
                i += 1 + len(m.group())
                continue
        out.append(text[i])
        i += 1
    return "".join(out)


def run_awk(prog_text, records, fs=None, hooks=None, assigns=None):
    """(stdout, stderr, exit_code). Raises nothing; syntax errors come back as
    stderr plus exit 2, which is what awk does -- never a passthrough."""
    try:
        ast = _Parser(_lex(prog_text)).program()
    except AwkSyntaxError as exc:
        return "", "awk: syntax error: %s\n" % exc, 2
    except RecursionError:
        return "", "awk: program too deeply nested\n", 2
    interp = Interp(ast, argv_fs=fs, hooks=hooks, assigns=assigns)
    try:
        interp.run(records)
    except _AwkRuntime as exc:
        return "".join(interp.out), "awk: %s\n" % exc, 2
    except RecursionError:
        return "".join(interp.out), "awk: call nesting too deep\n", 2
    return "".join(interp.out), "".join(interp.err), interp.exit_code
