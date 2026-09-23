#!/usr/bin/env python3
"""A simulator for the python3 an attacker types, not an interpreter for it.

`python3 -c` did nothing at all here: `print(6*7)` printed nothing, a file
write created nothing, and only --version answered. On a box whose whole
story is a training node that is instantly wrong, and it is worse than
wrong -- `python3 -c` is a standard stager idiom, so every one-liner an
attacker ran was a capture we did not take.

The old code refused on purpose, and the instinct was right: attacker code
must never reach exec() or eval(). This keeps that rule absolutely -- the
source is parsed with ast.parse, which builds a tree and runs nothing, and
then a whitelist of node types is walked by hand. There is no code path
here that hands attacker text to the interpreter.

What that buys, beyond not being obviously fake: os.system() and
subprocess calls are routed back through the shell, so a stager that
fetches its second stage through python is captured exactly as one that
used curl. That is the whole reason to do this rather than print a
plausible error.

Anything outside the subset raises the exception real python raises --
NameError, AttributeError, ModuleNotFoundError -- formatted as a real
traceback, so an unsupported construct looks like a mistake in their code
rather than a gap in ours.
"""

import ast

MAX_NODES = 20000
MAX_STEPS = 200000
MAX_LOOP = 100000
MAX_OUTPUT = 1 << 20


class PyError(Exception):
    """A python-level exception the simulated program raised."""

    def __init__(self, kind, msg, lineno=1):
        Exception.__init__(self, msg)
        self.kind = kind
        self.msg = msg
        self.lineno = lineno


class _Exit(Exception):
    def __init__(self, code):
        Exception.__init__(self, code)
        self.code = code


class _Break(Exception):
    pass


class _Continue(Exception):
    pass


class _Return(Exception):
    def __init__(self, value):
        Exception.__init__(self)
        self.value = value


class _Module(object):
    """A stand-in for an imported module: attribute lookup, nothing else."""

    def __init__(self, name, attrs):
        self.__name__ = name
        self._attrs = attrs

    def get(self, attr, lineno=1):
        if attr in self._attrs:
            return self._attrs[attr]
        raise PyError("AttributeError",
                      "module '%s' has no attribute '%s'"
                      % (self.__name__, attr), lineno)


class Sim(object):
    """Walks a parsed tree. Never calls exec, eval or compile."""

    def __init__(self, shell, argv=None, stdin=""):
        self.sh = shell
        self.out = []
        self.err = []
        self.steps = 0
        self.stdin = stdin
        # One object, so read/readline/readlines/iteration and input() all
        # advance the same position.
        self.stdin_obj = _StdIn(stdin)
        self.scope = {}
        self.argv = argv or ["-c"]
        self.exit_code = 0
        self._modules = {}
        # Files opened without `with`. CPython flushes them when the object
        # is collected or the interpreter exits, so `open(p,"w").write(x)`
        # -- one of the commonest one-liner idioms there is -- really does
        # leave a file behind. Ours dropped it: nothing called close().
        self._open_files = []

    # -- plumbing ---------------------------------------------------------
    def write(self, text):
        cur = sum(len(x) for x in self.out)
        if cur + len(text) > MAX_OUTPUT:
            text = text[:max(0, MAX_OUTPUT - cur)]
        if text:
            self.out.append(text)

    def _tick(self, node):
        self.steps += 1
        if self.steps > MAX_STEPS:
            raise PyError("RecursionError",
                          "maximum recursion depth exceeded",
                          getattr(node, "lineno", 1))

    # -- expressions ------------------------------------------------------
    def ev(self, n):
        self._tick(n)
        t = type(n)
        if t is ast.Constant:
            return n.value
        if t is ast.Name:
            if n.id in self.scope:
                return self.scope[n.id]
            if n.id in BUILTIN_NAMES:
                return _Builtin(n.id)
            raise PyError("NameError",
                          "name '%s' is not defined" % n.id, n.lineno)
        if t is ast.BinOp:
            return self._binop(n)
        if t is ast.UnaryOp:
            v = self.ev(n.operand)
            o = type(n.op)
            if o is ast.USub:
                return -v
            if o is ast.UAdd:
                return +v
            if o is ast.Not:
                return not v
            if o is ast.Invert:
                return ~v
            raise PyError("SyntaxError", "unsupported unary op", n.lineno)
        if t is ast.BoolOp:
            if type(n.op) is ast.And:
                v = True
                for x in n.values:
                    v = self.ev(x)
                    if not v:
                        return v
                return v
            v = False
            for x in n.values:
                v = self.ev(x)
                if v:
                    return v
            return v
        if t is ast.Compare:
            left = self.ev(n.comparators[0]) if False else self.ev(n.left)
            for op, comp in zip(n.ops, n.comparators):
                right = self.ev(comp)
                if not self._cmp(op, left, right, n.lineno):
                    return False
                left = right
            return True
        if t is ast.IfExp:
            return self.ev(n.body) if self.ev(n.test) else self.ev(n.orelse)
        if t is ast.JoinedStr:
            parts = []
            for v in n.values:
                if type(v) is ast.Constant:
                    parts.append(str(v.value))
                elif type(v) is ast.FormattedValue:
                    val = self.ev(v.value)
                    if v.format_spec is not None:
                        spec = "".join(
                            str(x.value) for x in v.format_spec.values
                            if type(x) is ast.Constant)
                        try:
                            parts.append(format(val, spec))
                        except Exception:
                            parts.append(str(val))
                    else:
                        parts.append(str(val))
            return "".join(parts)
        if t is ast.List:
            return [self.ev(x) for x in n.elts]
        if t is ast.Tuple:
            return tuple(self.ev(x) for x in n.elts)
        if t is ast.Set:
            return set(self.ev(x) for x in n.elts)
        if t is ast.Dict:
            return dict((self.ev(k), self.ev(v))
                        for k, v in zip(n.keys, n.values))
        if t is ast.Subscript:
            base = self.ev(n.value)
            idx = self.ev(n.slice) if type(n.slice) is not ast.Slice else None
            if type(n.slice) is ast.Slice:
                lo = self.ev(n.slice.lower) if n.slice.lower else None
                hi = self.ev(n.slice.upper) if n.slice.upper else None
                st = self.ev(n.slice.step) if n.slice.step else None
                try:
                    return base[lo:hi:st]
                except Exception as exc:
                    raise PyError(type(exc).__name__, str(exc), n.lineno)
            try:
                return base[idx]
            except Exception as exc:
                raise PyError(type(exc).__name__, str(exc), n.lineno)
        if t is ast.Attribute:
            return self._attr(n)
        if t is ast.Call:
            return self._call(n)
        if t is ast.ListComp:
            return list(self._comp(n))
        if t is ast.GeneratorExp:
            return list(self._comp(n))
        if t is ast.Starred:
            return self.ev(n.value)
        raise PyError("SyntaxError",
                      "unsupported expression", getattr(n, "lineno", 1))

    def _cmp(self, op, a, b, lineno):
        o = type(op)
        try:
            if o is ast.Eq:
                return a == b
            if o is ast.NotEq:
                return a != b
            if o is ast.Lt:
                return a < b
            if o is ast.LtE:
                return a <= b
            if o is ast.Gt:
                return a > b
            if o is ast.GtE:
                return a >= b
            if o is ast.In:
                return a in b
            if o is ast.NotIn:
                return a not in b
            if o is ast.Is:
                return a is b
            if o is ast.IsNot:
                return a is not b
        except Exception as exc:
            raise PyError(type(exc).__name__, str(exc), lineno)
        raise PyError("SyntaxError", "unsupported comparison", lineno)

    def _binop(self, n):
        a, b = self.ev(n.left), self.ev(n.right)
        o = type(n.op)
        try:
            if o is ast.Add:
                return a + b
            if o is ast.Sub:
                return a - b
            if o is ast.Mult:
                # A one-liner that builds a gigabyte string is a memory
                # bomb aimed at us, not at the box being imitated.
                if isinstance(a, (str, bytes, list)) and isinstance(b, int) \
                        and len(a) * max(b, 0) > MAX_OUTPUT:
                    raise PyError("MemoryError", "", n.lineno)
                if isinstance(b, (str, bytes, list)) and isinstance(a, int) \
                        and len(b) * max(a, 0) > MAX_OUTPUT:
                    raise PyError("MemoryError", "", n.lineno)
                return a * b
            if o is ast.Div:
                return a / b
            if o is ast.FloorDiv:
                return a // b
            if o is ast.Mod:
                return a % b
            if o is ast.Pow:
                if isinstance(b, int) and b > 4096:
                    raise PyError("MemoryError", "", n.lineno)
                return a ** b
            if o is ast.BitOr:
                return a | b
            if o is ast.BitAnd:
                return a & b
            if o is ast.BitXor:
                return a ^ b
            if o is ast.LShift:
                if isinstance(b, int) and b > 4096:
                    raise PyError("MemoryError", "", n.lineno)
                return a << b
            if o is ast.RShift:
                return a >> b
        except PyError:
            raise
        except Exception as exc:
            raise PyError(type(exc).__name__, str(exc), n.lineno)
        raise PyError("SyntaxError", "unsupported operator", n.lineno)

    def _comp(self, n):
        gen = n.generators[0]
        it = self.ev(gen.iter)
        saved = dict(self.scope)
        count = 0
        for item in it:
            count += 1
            if count > MAX_LOOP:
                raise PyError("MemoryError", "", n.lineno)
            self._bind(gen.target, item)
            if all(self.ev(c) for c in gen.ifs):
                yield self.ev(n.elt)
        self.scope = saved

    # -- statements -------------------------------------------------------
    def _bind(self, target, value):
        t = type(target)
        if t is ast.Name:
            self.scope[target.id] = value
            return
        if t in (ast.Tuple, ast.List):
            vals = list(value)
            if len(vals) != len(target.elts):
                raise PyError("ValueError",
                              "not enough values to unpack", 1)
            for tgt, val in zip(target.elts, vals):
                self._bind(tgt, val)
            return
        if t is ast.Subscript:
            base = self.ev(target.value)
            base[self.ev(target.slice)] = value
            return
        if t is ast.Attribute:
            raise PyError("AttributeError", "readonly attribute",
                          getattr(target, "lineno", 1))
        raise PyError("SyntaxError", "cannot assign",
                      getattr(target, "lineno", 1))

    def run_body(self, body):
        for st in body:
            self.exec_stmt(st)

    def exec_stmt(self, n):
        self._tick(n)
        t = type(n)
        if t is ast.Expr:
            self.ev(n.value)
            return
        if t is ast.Assign:
            v = self.ev(n.value)
            for tgt in n.targets:
                self._bind(tgt, v)
            return
        if t is ast.AugAssign:
            cur = self.ev(n.target) if type(n.target) is not ast.Name else \
                self.scope.get(n.target.id)
            if cur is None and type(n.target) is ast.Name \
                    and n.target.id not in self.scope:
                raise PyError("NameError",
                              "name '%s' is not defined" % n.target.id,
                              n.lineno)
            fake = ast.BinOp(left=ast.Constant(value=cur), op=n.op,
                             right=n.value)
            fake.lineno = n.lineno
            self._bind(n.target, self._binop(fake))
            return
        if t is ast.AnnAssign:
            if n.value is not None:
                self._bind(n.target, self.ev(n.value))
            return
        if t is ast.If:
            if self.ev(n.test):
                self.run_body(n.body)
            else:
                self.run_body(n.orelse)
            return
        if t is ast.For:
            it = self.ev(n.iter)
            count = 0
            for item in it:
                count += 1
                if count > MAX_LOOP:
                    raise PyError("KeyboardInterrupt", "", n.lineno)
                self._bind(n.target, item)
                try:
                    self.run_body(n.body)
                except _Break:
                    break
                except _Continue:
                    continue
            else:
                self.run_body(n.orelse)
            return
        if t is ast.While:
            count = 0
            while self.ev(n.test):
                count += 1
                if count > MAX_LOOP:
                    raise PyError("KeyboardInterrupt", "", n.lineno)
                try:
                    self.run_body(n.body)
                except _Break:
                    break
                except _Continue:
                    continue
            return
        if t is ast.Break:
            raise _Break()
        if t is ast.Continue:
            raise _Continue()
        if t is ast.Pass:
            return
        if t is ast.Import:
            for al in n.names:
                mod = self._import(al.name, n.lineno)
                self.scope[al.asname or al.name.split(".")[0]] = mod
            return
        if t is ast.ImportFrom:
            mod = self._import(n.module or "", n.lineno)
            for al in n.names:
                self.scope[al.asname or al.name] = mod.get(al.name, n.lineno)
            return
        if t is ast.Try:
            try:
                self.run_body(n.body)
            except PyError as exc:
                for h in n.handlers:
                    if self._handler_matches(h, exc):
                        if h.name:
                            self.scope[h.name] = exc.msg
                        self.run_body(h.body)
                        break
                else:
                    raise
            else:
                self.run_body(n.orelse)
            finally:
                self.run_body(n.finalbody)
            return
        if t is ast.Raise:
            raise PyError("Exception", "raised", n.lineno)
        if t is ast.FunctionDef:
            self.scope[n.name] = _Func(n)
            return
        if t is ast.Return:
            raise _Return(self.ev(n.value) if n.value else None)
        if t is ast.With:
            vals = []
            for item in n.items:
                v = self.ev(item.context_expr)
                vals.append(v)
                if item.optional_vars is not None:
                    self._bind(item.optional_vars, v)
            try:
                self.run_body(n.body)
            finally:
                for v in vals:
                    if isinstance(v, _FileObj):
                        v.close()
            return
        if t is ast.Delete:
            for tgt in n.targets:
                if type(tgt) is ast.Name:
                    self.scope.pop(tgt.id, None)
            return
        if t is ast.Global or t is ast.Nonlocal:
            return
        raise PyError("SyntaxError", "unsupported statement",
                      getattr(n, "lineno", 1))

    def _handler_matches(self, h, exc):
        if h.type is None:
            return True
        names = []
        if type(h.type) is ast.Name:
            names = [h.type.id]
        elif type(h.type) is ast.Tuple:
            names = [x.id for x in h.type.elts if type(x) is ast.Name]
        return exc.kind in names or "Exception" in names or \
            "BaseException" in names


    # -- calls, attributes, modules ---------------------------------------
    def _attr(self, n):
        base = self.ev(n.value)
        if isinstance(base, _Module):
            return base.get(n.attr, n.lineno)
        if isinstance(base, _FileObj):
            if n.attr in ("read", "write", "close", "readlines"):
                return ("__file__", base, n.attr)
            raise PyError("AttributeError",
                          "'_io.TextIOWrapper' object has no attribute '%s'"
                          % n.attr, n.lineno)
        if isinstance(base, (str, bytes, list, dict, tuple, set, int)):
            meth = getattr(type(base), n.attr, None)
            if meth is None or n.attr.startswith("_"):
                raise PyError("AttributeError",
                              "'%s' object has no attribute '%s'"
                              % (type(base).__name__, n.attr), n.lineno)
            return ("__meth__", base, n.attr)
        # An object a whitelisted module handed back -- a hashlib HASH, a
        # re.Match -- keeps its own methods. Without this
        # `hashlib.md5(b"x").hexdigest()` raised AttributeError on a call
        # that is the whole point of importing hashlib.
        meth = getattr(base, n.attr, None)
        if meth is not None and not n.attr.startswith("_"):
            return meth
        raise PyError("AttributeError",
                      "'%s' object has no attribute '%s'"
                      % (type(base).__name__, n.attr), n.lineno)

    def _import(self, name, lineno):
        top = name.split(".")[0]
        if top in self._modules:
            return self._modules[top]
        if top not in MODULES:
            raise PyError("ModuleNotFoundError",
                          "No module named '%s'" % top, lineno)
        mod = _Module(top, MODULES[top](self))
        self._modules[top] = mod
        return mod

    def _call(self, n):
        fn = self.ev(n.func)
        args = []
        for a in n.args:
            if type(a) is ast.Starred:
                args.extend(self.ev(a.value))
            else:
                args.append(self.ev(a))
        kw = dict((k.arg, self.ev(k.value)) for k in n.keywords if k.arg)
        line = n.lineno

        if isinstance(fn, tuple) and fn and fn[0] == "__meth__":
            _, base, attr = fn
            try:
                return getattr(base, attr)(*args, **kw)
            except (PyError, _Exit, _Break, _Continue, _Return):
                raise
            except Exception as exc:
                raise PyError(type(exc).__name__, str(exc), line)
        if isinstance(fn, tuple) and fn and fn[0] == "__file__":
            _, fobj, attr = fn
            try:
                return getattr(fobj, attr)(*args)
            except (PyError, _Exit, _Break, _Continue, _Return):
                raise
            except Exception as exc:
                raise PyError(type(exc).__name__, str(exc), line)
        if callable(fn) and not isinstance(fn, (_Builtin, _Func)):
            try:
                return fn(*args, **kw)
            except (PyError, _Exit, _Break, _Continue, _Return):
                # sys.exit() raises _Exit through a module lambda; wrapping
                # it as a PyError turned `sys.exit(3)` into a traceback with
                # rc 1 instead of a clean exit 3.
                raise
            except Exception as exc:
                raise PyError(type(exc).__name__, str(exc), line)
        if isinstance(fn, _Func):
            saved = dict(self.scope)
            for prm, val in zip(fn.node.args.args, args):
                self.scope[prm.arg] = val
            try:
                self.run_body(fn.node.body)
                return None
            except _Return as r:
                return r.value
            finally:
                self.scope = saved
        if isinstance(fn, _Builtin):
            return self._builtin(fn.name, args, kw, line)
        raise PyError("TypeError", "'%s' object is not callable"
                      % type(fn).__name__, line)

    def _builtin(self, name, args, kw, line):
        if name == "print":
            sep = kw.get("sep", " ")
            end = kw.get("end", "\n")
            self.write(sep.join(_disp(a) for a in args) + end)
            return None
        if name == "open":
            path = args[0] if args else ""
            mode = args[1] if len(args) > 1 else kw.get("mode", "r")
            fobj = _FileObj(self, str(path), str(mode))
            self._open_files.append(fobj)
            return fobj
        if name in ("exit", "quit"):
            raise _Exit(args[0] if args and isinstance(args[0], int) else 0)
        if name == "input":
            if args:
                self.write(str(args[0]))
            # This returned stdin.split("\n")[0] every time, so two calls
            # read the same line twice. It shares a position with sys.stdin
            # now, drops the newline, and raises at EOF as the real one does.
            text = self.stdin_obj.readline()
            if text == "":
                raise PyError("EOFError", "EOF when reading a line", line)
            return text[:-1] if text.endswith("\n") else text
        fn = getattr(__builtins__, name, None) if not isinstance(
            __builtins__, dict) else __builtins__.get(name)
        if fn is None:
            raise PyError("NameError", "name '%s' is not defined" % name, line)
        try:
            r = fn(*args, **kw)
        except Exception as exc:
            raise PyError(type(exc).__name__, str(exc), line)
        if name in ("range", "map", "filter", "zip", "enumerate",
                    "reversed"):
            out = []
            for i, v in enumerate(r):
                if i > MAX_LOOP:
                    raise PyError("MemoryError", "", line)
                out.append(v)
            return out
        return r

    # -- the bridge back to the shell -------------------------------------
    def shell_out(self, cmd):
        """Run `cmd` through the emulator and hand back (out, rc).

        This is why the simulator exists rather than a plausible error
        string: a stager that reaches its second stage through
        os.system() or subprocess is captured exactly like one that used
        curl, because it goes through the same shell.
        """
        try:
            res = self.sh.run(cmd)
        except Exception:                                      # noqa: BLE001
            return "", 1
        out = (res[0] if isinstance(res, tuple) else res) or ""
        return out, getattr(self.sh, "last_rc", 0)


def _disp(v):
    if isinstance(v, bytes):
        return repr(v)
    if v is True:
        return "True"
    if v is False:
        return "False"
    if v is None:
        return "None"
    return str(v)


class _Func(object):
    def __init__(self, node):
        self.node = node


class _Builtin(object):
    def __init__(self, name):
        self.name = name


def fs_norm(sh, path):
    """An absolute VFS path for `path`, honouring the shell's cwd."""
    try:
        return sh.fs.norm(str(path), sh.cwd)
    except Exception:                                          # noqa: BLE001
        return str(path)


class _FileObj(object):
    """open() against the VFS, not the host filesystem."""

    def __init__(self, sim, path, mode):
        self.sim = sim
        self.path = path
        self.mode = mode
        self.buf = []
        self.closed = False
        self.binary = "b" in mode
        if "r" in mode and "+" not in mode:
            data = sim.sh.fs.read(fs_norm(sim.sh, path))
            if data is None:
                raise PyError(
                    "FileNotFoundError",
                    "[Errno 2] No such file or directory: '%s'" % path, 1)
            self.data = data if self.binary else data.decode("utf-8", "replace")
        else:
            self.data = b"" if self.binary else ""

    def read(self, *a):
        return self.data

    def readlines(self):
        text = self.data if not self.binary else self.data.decode(
            "utf-8", "replace")
        return [l + "\n" for l in text.split("\n")[:-1]] or [text]

    def write(self, s):
        self.buf.append(s)
        return len(s)

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.buf and ("w" in self.mode or "a" in self.mode):
            body = b"".join(x if isinstance(x, bytes) else x.encode(
                "utf-8", "replace") for x in self.buf)
            # Through the VFS's own writer, which is what a shell
            # redirection uses, so _note_payload_writes sees it at
            # end-of-line and a file a stager drops through python becomes
            # the same evidence as one it drops with curl.
            try:
                sh = self.sim.sh
                # resolve() does not know the shell's cwd; norm() does.
                # A relative write -- `open("p.sh","w")` after a cd, which
                # is exactly how a stager drops its next stage -- landed
                # nowhere at all, while an absolute path worked, so the
                # bug was invisible to any test that used /tmp/...
                path = fs_norm(sh, self.path)
                if "a" in self.mode:
                    prev = sh.fs.read(path) or b""
                    body_out = prev + body
                else:
                    body_out = body
                sh.fs.write(path, body_out, mode=0o644)
            except Exception:                                  # noqa: BLE001
                pass


BUILTIN_NAMES = frozenset((
    "print", "len", "str", "int", "float", "bool", "list", "dict", "tuple",
    "set", "range", "open", "chr", "ord", "abs", "min", "max", "sum",
    "sorted", "reversed", "enumerate", "zip", "hex", "oct", "bin", "repr",
    "type", "isinstance", "bytes", "input", "round", "any", "all", "map",
    "filter", "exit", "quit",
))


def _os_mod(sim):
    def _system(cmd):
        out, rc = sim.shell_out(str(cmd))
        sim.write(out)
        return rc << 8 if rc else 0

    def _popen(cmd, *a):
        out, _rc = sim.shell_out(str(cmd))
        return _StringHandle(out)

    def _listdir(path="."):
        r = sim.sh.run("ls -1 %s" % _q(path))
        out = (r[0] if isinstance(r, tuple) else r) or ""
        return [x for x in out.split("\n") if x]

    def _getenv(k, d=None):
        return sim.sh.vars.get(k, sim.sh.env.get(k, d)
                               if hasattr(sim.sh, "env") else d)

    return {
        "system": _system, "popen": _popen, "listdir": _listdir,
        "getenv": _getenv, "getcwd": lambda: sim.sh.cwd,
        "getpid": lambda: 21943, "getuid": lambda: sim.sh.uid,
        "geteuid": lambda: sim.sh.uid, "getgid": lambda: sim.sh.gid,
        "name": "posix", "sep": "/", "linesep": "\n",
        "environ": _EnvMap(sim),
        "path": _Module("os.path", {
            "exists": lambda p: sim.sh.fs.nodes.get(
                sim.sh.fs.resolve(str(p))) is not None,
            "isfile": lambda p: not sim.sh.fs.isdir(str(p))
            and sim.sh.fs.nodes.get(sim.sh.fs.resolve(str(p))) is not None,
            "isdir": lambda p: sim.sh.fs.isdir(str(p)),
            "basename": lambda p: str(p).rstrip("/").split("/")[-1],
            "dirname": lambda p: "/".join(str(p).split("/")[:-1]) or "/",
            "join": lambda *xs: "/".join(x.strip("/") for x in xs if x)
            and ("/" if str(xs[0]).startswith("/") else "")
            + "/".join(str(x).strip("/") for x in xs if x),
            "abspath": lambda p: sim.sh.fs.resolve(str(p)),
        }),
    }


class _StringHandle(object):
    def __init__(self, text):
        self.text = text

    def read(self, *a):
        return self.text

    def close(self):
        return None

    def readlines(self):
        return [l + "\n" for l in self.text.split("\n")[:-1]]


class _EnvMap(object):
    def __init__(self, sim):
        self.sim = sim

    def get(self, k, d=None):
        return self.sim.sh.vars.get(k, d)

    def __getitem__(self, k):
        v = self.sim.sh.vars.get(k)
        if v is None:
            raise PyError("KeyError", repr(k), 1)
        return v

    def __contains__(self, k):
        return k in self.sim.sh.vars


def _q(p):
    return "'" + str(p).replace("'", "'\\''") + "'"


class _StdIn(object):
    """sys.stdin, over the text the shell piped in.

    It was simply absent, so `python3 -c "import sys; print(sys.stdin.read())"`
    raised AttributeError: module 'sys' has no attribute 'stdin' -- on a box
    whose python otherwise works. Piping into python is the ordinary way to
    hand it data, and `json.load(sys.stdin)` fails the same way.

    A real class rather than a _Module for two reasons. `for line in
    sys.stdin` is a native `for item in it` in the For handler, so this has
    to be genuinely iterable; and read, readline, readlines and input() all
    have to share one position, because two input() calls return successive
    lines on a real box and did not here (input() re-read the first line
    every time, so a two-prompt script saw the same answer twice).
    """

    def __init__(self, text):
        self._text = text or ""
        self._pos = 0

    def read(self, size=-1):
        if size is None or size < 0:
            out = self._text[self._pos:]
            self._pos = len(self._text)
            return out
        out = self._text[self._pos:self._pos + size]
        self._pos += len(out)
        return out

    def readline(self, size=-1):
        if self._pos >= len(self._text):
            return ""
        nl = self._text.find("\n", self._pos)
        end = len(self._text) if nl < 0 else nl + 1
        if size is not None and size >= 0:
            end = min(end, self._pos + size)
        out = self._text[self._pos:end]
        self._pos = end
        return out

    def readlines(self, hint=-1):
        out = []
        while True:
            line = self.readline()
            if not line:
                return out
            out.append(line)

    def __iter__(self):
        while True:
            line = self.readline()
            if not line:
                return
            yield line

    def isatty(self):
        # Piped, always: nothing reaches pysim with a terminal on stdin.
        return False

    def fileno(self):
        return 0

    def close(self):
        return None

    def flush(self):
        return None

    @property
    def encoding(self):
        return "utf-8"


def _sys_mod(sim):
    def _exit(code=0):
        raise _Exit(code if isinstance(code, int) else 0)
    return {
        "argv": sim.argv, "exit": _exit, "stdin": sim.stdin_obj,
        "version": "3.13.5 (main, Jun 12 2026, 10:12:33) [GCC 14.2.0]",
        "version_info": (3, 13, 5, "final", 0),
        "platform": "linux", "maxsize": 9223372036854775807,
        "executable": "/usr/bin/python3",
        "stdout": _Module("sys.stdout", {
            "write": lambda s: (sim.write(str(s)), len(str(s)))[1],
            "flush": lambda: None}),
        "stderr": _Module("sys.stderr", {
            "write": lambda s: (sim.err.append(str(s)), len(str(s)))[1],
            "flush": lambda: None}),
    }


def _socket_mod(sim):
    return {
        "gethostname": lambda: sim.sh.host if hasattr(sim.sh, "host")
        else "web01",
        "AF_INET": 2, "SOCK_STREAM": 1, "SOCK_DGRAM": 2,
        # A socket that never connects. The honeypot does not reach out on
        # an attacker's behalf, and the refusal a firewalled box gives is
        # the honest answer, not a hang.
        "socket": lambda *a, **k: _Sock(sim),
        "create_connection": lambda *a, **k: _refused(),
    }


def _refused():
    raise PyError("ConnectionRefusedError", "[Errno 111] Connection refused", 1)


class _Sock(object):
    def __init__(self, sim):
        self.sim = sim

    def connect(self, *a):
        _refused()

    def settimeout(self, *a):
        return None

    def close(self):
        return None

    def send(self, *a):
        _refused()

    def recv(self, *a):
        _refused()


def _subprocess_mod(sim):
    def _run(cmd, *a, **k):
        cmd = " ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
        out, rc = sim.shell_out(cmd)
        return _Module("CompletedProcess", {
            "returncode": rc, "stdout": out, "stderr": ""})

    def _check_output(cmd, *a, **k):
        cmd = " ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
        out, _rc = sim.shell_out(cmd)
        return out.encode() if k.get("text") is not True else out

    def _call(cmd, *a, **k):
        cmd = " ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
        out, rc = sim.shell_out(cmd)
        sim.write(out)
        return rc
    return {"run": _run, "check_output": _check_output, "call": _call,
            "Popen": lambda cmd, *a, **k: _StringHandle(
                sim.shell_out(" ".join(cmd) if isinstance(cmd, (list, tuple))
                              else str(cmd))[0]),
            "PIPE": -1, "STDOUT": -2, "DEVNULL": -3}


def _base64_mod(sim):
    import base64 as _b

    def _wrap(fn):
        def inner(x):
            data = x.encode() if isinstance(x, str) else x
            try:
                return fn(data)
            except Exception as exc:
                raise PyError(type(exc).__name__, str(exc), 1)
        return inner
    return {"b64encode": _wrap(_b.b64encode),
            "b64decode": _wrap(_b.b64decode),
            "b16encode": _wrap(_b.b16encode),
            "b32encode": _wrap(_b.b32encode)}


def _time_mod(sim):
    import time as _t
    return {"time": _t.time, "sleep": lambda n: None,
            "ctime": _t.ctime, "strftime": _t.strftime,
            "localtime": _t.localtime, "gmtime": _t.gmtime}


MODULES = {
    "os": _os_mod, "sys": _sys_mod, "socket": _socket_mod,
    "subprocess": _subprocess_mod, "base64": _base64_mod, "time": _time_mod,
    "platform": lambda sim: {"system": lambda: "Linux",
                             "machine": lambda: "x86_64",
                             "node": lambda: "web01",
                             "release": lambda: "6.12.101+deb13-cloud-amd64"},
    "json": lambda sim: __import__("json").__dict__,
    "hashlib": lambda sim: {
        "md5": __import__("hashlib").md5,
        "sha1": __import__("hashlib").sha1,
        "sha256": __import__("hashlib").sha256},
    "random": lambda sim: {"randint": __import__("random").randint,
                           "choice": __import__("random").choice,
                           "random": __import__("random").random},
    "getpass": lambda sim: {"getuser": lambda: sim.sh.user},
    "string": lambda sim: __import__("string").__dict__,
    "math": lambda sim: __import__("math").__dict__,
    "re": lambda sim: __import__("re").__dict__,
}


def run_source(shell, source, argv=None, stdin="", filename="<string>"):
    """(stdout, stderr, rc). Parses and walks; never exec/eval."""
    sim = Sim(shell, argv=argv, stdin=stdin)
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        # Real python underlines the offending column with a caret. Without
        # it our SyntaxError was a line short of the genuine article, which
        # scripttest caught by diffing the two.
        text = (exc.text or "").rstrip("\n")
        caret = ""
        if exc.offset and text:
            caret = "\n    " + " " * max(0, int(exc.offset) - 1) + "^"
        return "", ('  File "%s", line %s\n    %s%s\nSyntaxError: %s\n'
                    % (filename, exc.lineno, text, caret, exc.msg)), 1
    if sum(1 for _ in ast.walk(tree)) > MAX_NODES:
        return "", "MemoryError\n", 1

    def _flush():
        for f in sim._open_files:
            try:
                f.close()
            except Exception:                                  # noqa: BLE001
                pass
    try:
        sim.run_body(tree.body)
    except _Exit as e:
        _flush()
        return "".join(sim.out), "".join(sim.err), int(e.code or 0)
    except PyError as e:
        tb = ('Traceback (most recent call last):\n'
              '  File "%s", line %d, in <module>\n%s%s\n'
              % (filename, e.lineno, e.kind,
                 (": " + e.msg) if e.msg else ""))
        _flush()
        return "".join(sim.out), "".join(sim.err) + tb, 1
    except (_Break, _Continue, _Return):
        _flush()
        return "".join(sim.out), "".join(sim.err), 0
    except RecursionError:
        _flush()
        return "".join(sim.out), "RecursionError: maximum recursion depth exceeded\n", 1
    _flush()
    return "".join(sim.out), "".join(sim.err), 0
