"""Разбор запросов Graylog (синтаксис Lucene), их вычисление над сообщением и сборка образцов.

Только стандартная библиотека. Вычислитель повторяет поведение Graylog/OpenSearch приближённо:
  * message и full_message разбираются на слова без учёта регистра;
  * source сравнивается целиком без учёта регистра;
  * остальные поля сравниваются целиком с учётом регистра, регулярные выражения должны покрыть всё значение.
Решающее слово всегда за самим Graylog (режимы run-queries и run-e2e); этот модуль нужен, чтобы
собрать образцы и увидеть ошибки в запросах до отправки.
"""
import itertools
import re

try:  # Python 3.11+
    import re._parser as _sp
except Exception:  # pragma: no cover
    import sre_parse as _sp

TEXT_FIELDS = {"message", "full_message"}
CI_FIELDS = {"source"}
DEFAULT_FIELD = "message"


class QueryError(ValueError):
    pass


# ---------------------------------------------------------------- разбор

class Lit:
    """Листовое условие: field:value."""
    __slots__ = ("field", "kind", "text", "warn")

    def __init__(self, field, kind, text, warn=None):
        self.field, self.kind, self.text, self.warn = field, kind, text, warn

    def key(self):
        return (self.field, self.kind, self.text)

    def __repr__(self):
        return "%s:%s<%s>" % (self.field, self.kind, self.text)


class Parser:
    def __init__(self, s):
        self.s, self.i, self.warns = s, 0, []

    def ws(self):
        while self.i < len(self.s) and self.s[self.i].isspace():
            self.i += 1

    def peek(self, n=1):
        return self.s[self.i:self.i + n]

    def word_at(self, w):
        if self.s.startswith(w, self.i):
            j = self.i + len(w)
            return j >= len(self.s) or self.s[j].isspace() or self.s[j] in "()"
        return False

    def parse(self):
        node = self.or_expr(None)
        self.ws()
        if self.i < len(self.s):
            raise QueryError("лишний текст в позиции %d: %r" % (self.i, self.s[self.i:self.i + 20]))
        return node

    def or_expr(self, field):
        parts = [self.and_expr(field)]
        while True:
            self.ws()
            if self.word_at("OR"):
                self.i += 2
            elif self.peek(2) == "||":
                self.i += 2
            else:
                break
            parts.append(self.and_expr(field))
        return parts[0] if len(parts) == 1 else ("or", parts)

    def and_expr(self, field):
        parts = [self.unary(field)]
        while True:
            self.ws()
            if self.i >= len(self.s) or self.peek() == ")" or self.word_at("OR") or self.peek(2) == "||":
                break
            if self.word_at("AND"):
                self.i += 3
            elif self.peek(2) == "&&":
                self.i += 2
            else:
                self.warns.append("соседние условия без AND/OR (Graylog считает их AND)")
            parts.append(self.unary(field))
        return parts[0] if len(parts) == 1 else ("and", parts)

    def unary(self, field):
        self.ws()
        if self.word_at("NOT"):
            self.i += 3
            return ("not", self.unary(field))
        if self.peek() == "!":
            self.i += 1
            return ("not", self.unary(field))
        if self.peek() == "-":
            self.i += 1
            return ("not", self.unary(field))
        if self.peek() == "+":
            self.i += 1
        return self.primary(field)

    def primary(self, field):
        self.ws()
        if self.i >= len(self.s):
            raise QueryError("запрос оборвался")
        if self.peek() == "(":
            self.i += 1
            node = self.or_expr(field)
            self.ws()
            if self.peek() != ")":
                raise QueryError("нет закрывающей скобки")
            self.i += 1
            self.suffix()
            return node
        name = self.field_name()
        if name is not None:
            self.ws()
            if name == "_exists_":
                f = self.bare()
                return Lit(f, "exists", "")
            if self.peek() == "(":
                self.i += 1
                node = self.or_expr(name)
                self.ws()
                if self.peek() != ")":
                    raise QueryError("нет закрывающей скобки после %s:(" % name)
                self.i += 1
                self.suffix()
                return node
            return self.value(name)
        return self.value(field or DEFAULT_FIELD)

    def field_name(self):
        m = re.compile(r"([A-Za-z_][\w.\-]*)\s*:").match(self.s, self.i)
        if m and not self.s.startswith("://", m.end() - 1):
            self.i = m.end()
            return m.group(1)
        return None

    def value(self, field):
        self.ws()
        c = self.peek()
        if c == '"':
            j, buf = self.i + 1, []
            while j < len(self.s) and self.s[j] != '"':
                if self.s[j] == "\\" and j + 1 < len(self.s):
                    j += 1
                buf.append(self.s[j])
                j += 1
            if j >= len(self.s):
                raise QueryError("незакрытая кавычка")
            self.i = j + 1
            self.suffix()
            return Lit(field, "phrase", "".join(buf))
        if c == "/":
            j, buf = self.i + 1, []
            while j < len(self.s) and self.s[j] != "/":
                if self.s[j] == "\\" and j + 1 < len(self.s):
                    if self.s[j + 1] == "/":
                        buf.append("/")
                        j += 2
                        continue
                    buf.append(self.s[j])
                    buf.append(self.s[j + 1])
                    j += 2
                    continue
                buf.append(self.s[j])
                j += 1
            if j >= len(self.s):
                raise QueryError("незакрытое регулярное выражение")
            self.i = j + 1
            return Lit(field, "regex", "".join(buf))
        if c in "[{":
            raise QueryError("диапазоны [a TO b] не поддерживаются тестером")
        txt, wild = self.bare(want_wild=True)
        self.suffix()
        return Lit(field, "wild" if wild else "term", txt)

    def bare(self, want_wild=False):
        j, buf, wild = self.i, [], False
        while j < len(self.s) and not self.s[j].isspace() and self.s[j] not in "()":
            ch = self.s[j]
            if ch == "\\" and j + 1 < len(self.s):
                j += 1
                buf.append(self.s[j])
                j += 1
                continue
            if ch in "^~" and j > self.i:
                break
            if ch in "*?":
                wild = True
            buf.append(ch)
            j += 1
        if j == self.i:
            raise QueryError("пустое значение в позиции %d" % self.i)
        self.i = j
        txt = "".join(buf)
        return (txt, wild) if want_wild else txt

    def suffix(self):
        m = re.compile(r"[\^~][\d.]*").match(self.s, self.i)
        if m:
            self.warns.append("суффикс %s (вес/нечёткий поиск) тестер не учитывает" % m.group(0))
            self.i = m.end()


def parse(query):
    p = Parser(query.strip())
    node = p.parse()
    return node, p.warns


def literals(node):
    if isinstance(node, Lit):
        yield node
    else:
        kids = node[1] if node[0] in ("and", "or") else [node[1]]
        for k in kids:
            yield from literals(k)


# ---------------------------------------------------------------- проверка регулярок Lucene

def lucene_regex_lint(pattern):
    """Предупреждения о конструкциях, которые Lucene понимает иначе, чем Python."""
    out = []
    if re.search(r"(?<!\\)\\[dDwWsSbB]", pattern):
        out.append("\\d \\w \\s \\b не поддерживаются в Lucene (нужны [0-9], [a-zA-Z0-9_], [ ])")
    stripped = re.sub(r"\[(?:\\.|[^\]\\])*\]", "", pattern)
    stripped = re.sub(r"\\.", "", stripped)
    for ch, why in (("~", "оператор дополнения"), ("&", "оператор пересечения"),
                    ("#", "пустое множество"), ("@", "«любая строка»"),
                    ("<", "интервал <a-b>"), (">", "интервал <a-b>")):
        if ch in stripped:
            out.append("символ %r вне скобок в Lucene — %s; если нужен сам символ, экранируйте или поместите в []" % (ch, why))
    if re.search(r"\(\?[:=!<]", pattern):
        out.append("конструкции (?:...), (?=...) в Lucene не поддерживаются")
    return out


# ---------------------------------------------------------------- вычисление

def _vals(doc, field):
    v = doc.get(field)
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v]
    return [str(v)]


def _tokens(s):
    return re.findall(r"\w+", s.lower())


def _wild_re(pat, flags=0):
    out = []
    for ch in pat:
        out.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
    return re.compile("".join(out), flags | re.S)


def _py_regex(p):
    return re.compile(p, re.S)


def match_lit(lit, doc):
    vals = _vals(doc, lit.field)
    if lit.kind == "exists":
        return any(v != "" for v in vals)
    if lit.field in TEXT_FIELDS:
        toks_all = [_tokens(v) for v in vals]
        if lit.kind in ("term", "phrase"):
            want = _tokens(lit.text)
            if not want:
                return False
            return any(any(t[i:i + len(want)] == want for i in range(len(t) - len(want) + 1)) for t in toks_all)
        if lit.kind == "wild":
            rx = _wild_re(lit.text.lower())
            return any(rx.fullmatch(tok) for t in toks_all for tok in t)
        if lit.kind == "regex":
            rx = _py_regex(lit.text)
            return any(rx.fullmatch(tok) for t in toks_all for tok in t)
    if lit.text == "*" and lit.kind == "wild":
        return bool(vals)
    if lit.field in CI_FIELDS:
        vals = [v.lower() for v in vals]
        if lit.kind in ("term", "phrase"):
            return lit.text.lower() in vals
        if lit.kind == "wild":
            rx = _wild_re(lit.text.lower())
            return any(rx.fullmatch(v) for v in vals)
    if lit.kind in ("term", "phrase"):
        return lit.text in vals
    if lit.kind == "wild":
        rx = _wild_re(lit.text)
        return any(rx.fullmatch(v) for v in vals)
    if lit.kind == "regex":
        rx = _py_regex(lit.text)
        return any(rx.fullmatch(v) for v in vals)
    return False


def evaluate(node, doc):
    if isinstance(node, Lit):
        return match_lit(node, doc)
    op = node[0]
    if op == "and":
        return all(evaluate(k, doc) for k in node[1])
    if op == "or":
        return any(evaluate(k, doc) for k in node[1])
    return not evaluate(node[1], doc)


# ---------------------------------------------------------------- строки по регулярному выражению

def _gen(tree, neg_pool="abcxyz"):
    out = []
    for op, av in tree:
        name = str(op)
        if name == "LITERAL":
            out.append(chr(av))
        elif name == "NOT_LITERAL":
            out.append("a" if av != ord("a") else "b")
        elif name == "ANY":
            out.append("a")
        elif name == "IN":
            neg = any(str(o) == "NEGATE" for o, _ in av)
            if neg:
                banned = set()
                for o, a in av:
                    if str(o) == "LITERAL":
                        banned.add(chr(a))
                    elif str(o) == "RANGE":
                        banned.update(chr(c) for c in range(a[0], a[1] + 1))
                out.append(next(c for c in neg_pool + "0123456789_" if c not in banned))
                continue
            o, a = next((o, a) for o, a in av if str(o) != "NEGATE")
            so = str(o)
            if so == "LITERAL":
                out.append(chr(a))
            elif so == "RANGE":
                out.append(chr(a[0]))
            elif so == "CATEGORY":
                out.append(_cat(a))
        elif name == "BRANCH":
            out.append(_gen(av[1][0], neg_pool))
        elif name == "SUBPATTERN":
            out.append(_gen(av[-1], neg_pool))
        elif name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
            lo, _hi, sub = av
            out.append(_gen(sub, neg_pool) * lo)
        elif name in ("AT", "ASSERT", "ASSERT_NOT"):
            continue
        else:
            raise QueryError("не умею собирать строку для %s" % name)
    return "".join(out)


def _cat(a):
    s = str(a)
    if "DIGIT" in s:
        return "0"
    if "SPACE" in s:
        return " "
    return "a"


def regex_example(pattern):
    try:
        text = _gen(_sp.parse(pattern, re.S))
    except Exception as e:
        raise QueryError("регулярное выражение не разобрано: %s" % e)
    if not re.fullmatch(pattern, text, re.S):
        raise QueryError("не удалось собрать строку под регулярное выражение")
    return text


def lit_example(lit):
    if lit.kind in ("term", "phrase"):
        return lit.text
    if lit.kind == "wild":
        return lit.text.replace("*", "").replace("?", "a") or "x"
    if lit.kind == "regex":
        return regex_example(lit.text)
    if lit.kind == "exists":
        return "rt"
    raise QueryError(lit.kind)


# ---------------------------------------------------------------- ДНФ и образцы

def dnf(node, neg=False, cap=400):
    """Список конъюнкций [(Lit, positive)], без раскрытия сверх cap."""
    if isinstance(node, Lit):
        return [[(node, not neg)]]
    op = node[0]
    if op == "not":
        return dnf(node[1], not neg, cap)
    kids = [dnf(k, neg, cap) for k in node[1]]
    conj = (op == "and") != neg
    if not conj:
        return [c for k in kids for c in k][:cap]
    res = []
    for combo in itertools.product(*kids):
        c, seen, bad = [], set(), False
        for part in combo:
            for lit, pos in part:
                key = (lit.key(), pos)
                if (lit.key(), not pos) in seen:
                    bad = True
                if key not in seen:
                    seen.add(key)
                    c.append((lit, pos))
        if not bad:
            res.append(c)
        if len(res) >= cap:
            break
    return res


def pick_spread(items, n):
    if len(items) <= n:
        return list(items)
    if n == 1:
        return [items[0]]
    idx = sorted({round(i * (len(items) - 1) / (n - 1)) for i in range(n)})
    return [items[i] for i in idx]


def build_doc(conj, extra=None):
    """Собирает сообщение, удовлетворяющее положительным условиям конъюнкции."""
    by_field = {}
    for lit, pos in conj:
        if pos:
            by_field.setdefault(lit.field, []).append(lit)
    doc = dict(extra or {})
    for field, lits in by_field.items():
        lits = [l for l in lits if l.kind != "exists" or len(lits) == 1]
        if not lits:
            doc[field] = "rt"
            continue
        if lits[0].kind == "wild" and lits[0].text == "*":
            doc[field] = "rt"
            continue
        parts = [lit_example(l) for l in lits]
        cands = []
        if field in TEXT_FIELDS:
            cands.append(" ".join(dict.fromkeys(parts)))
        cands += [parts[0], "".join(parts), "".join(reversed(parts)), " ".join(parts)]
        for c in cands:
            if all(match_lit(l, {field: c}) for l in lits):
                doc[field] = c
                break
        else:
            raise QueryError("условия на поле %s не удаётся выполнить одной строкой" % field)
    return doc


def make_samples(node, group_by=(), max_pos=3, max_neg=4):
    """Возвращает (positives, negatives, problems).

    positive/negative: список словарей {"doc":…, "why":…}.
    """
    problems, pos, neg = [], [], []
    conjs = dnf(node)
    chosen = pick_spread(conjs, max_pos)
    base = {g: "rt-group" for g in group_by if g}
    seen = set()
    for conj in chosen:
        try:
            doc = build_doc(conj, base)
        except QueryError as e:
            problems.append(str(e))
            continue
        if not evaluate(node, doc):
            problems.append("собранное сообщение не проходит запрос")
            continue
        sig = repr(sorted(doc.items()))
        if sig in seen:
            continue
        seen.add(sig)
        label = "; ".join("%s%s" % ("" if p else "НЕ ", l.field) for l, p in conj if l.kind != "exists")[:120]
        pos.append({"doc": doc, "why": "ветка запроса: %s" % label})
    if not pos:
        return pos, neg, problems or ["нет положительных ветвей"]

    first = chosen[0]
    doc0 = pos[0]["doc"]
    # 1. убрать обязательное условие
    cnt = 0
    for lit, p in first:
        if cnt >= max_neg // 2 + 1:
            break
        if not p or lit.kind == "exists" and lit.field in (base or {}):
            continue
        same = [l for l, pp in first if pp and l.field == lit.field]
        if len(same) > 1:
            continue
        d = dict(doc0)
        d.pop(lit.field, None)
        if evaluate(node, d):
            continue
        neg.append({"doc": d, "why": "нет условия %s (%s)" % (lit.field, lit.kind)})
        cnt += 1
    # 2. нарушить исключение
    cnt = 0
    for lit, p in first:
        if p or cnt >= 3:
            continue
        try:
            val = lit_example(lit)
        except QueryError:
            continue
        d = dict(doc0)
        keep = [l for l, pp in first if pp and l.field == lit.field]
        if lit.field in d and keep:
            cur = d[lit.field]
            for c in (cur + " " + val, cur + val, val + " " + cur, val + cur):
                if all(match_lit(l, {lit.field: c}) for l in keep) and match_lit(lit, {lit.field: c}):
                    d[lit.field] = c
                    break
            else:
                continue
        else:
            d[lit.field] = val
        if evaluate(node, d) or not match_lit(lit, d):
            continue
        neg.append({"doc": d, "why": "исключение: %s %s" % (lit.field, lit.kind)})
        cnt += 1
    return pos, neg[:max_neg], problems
