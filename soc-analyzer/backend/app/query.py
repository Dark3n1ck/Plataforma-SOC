"""Lenguaje de búsqueda estilo DQL/Lucene compilado a SQL parametrizado.

Ejemplos:
  event_id:4625 AND NOT user:"CORP\\admin"
  (src_ip:203.0.113.* OR src_ip:198.51.100.*) AND result:Success
  alert >= alto AND cmd:*powershell*
  ts >= "2026-10-23 09:00" AND ts < "2026-10-23 10:00"
"""
import re
from dataclasses import dataclass

FIELDS = {
    "ts": "ts", "host": "host", "event_id": "event_id", "user": "user", "src_ip": "src_ip", "dest": "dest",
    "log_source": "log_source", "description": "description", "cmd": "cmd", "result": "result",
    "severity": "severity_src", "log_id": "log_id", "source": "source", "alert": "alert_severity",
}
ALIASES = {
    "timestamp": "ts", "@timestamp": "ts", "fecha": "ts", "hostname": "host", "equipo": "host", "agent.name": "host",
    "eventid": "event_id", "id": "event_id", "data.win.system.eventid": "event_id", "usuario": "user",
    "data.win.eventdata.subjectusername": "user", "ip": "src_ip", "source_ip": "src_ip", "srcip": "src_ip", "data.srcip": "src_ip",
    "destination": "dest", "destino": "dest", "descripcion": "description", "message": "description", "rule.description": "description",
    "commandline": "cmd", "process_commandline": "cmd", "data.win.eventdata.commandline": "cmd",
    "resultado": "result", "severidad": "severity", "alerta": "alert",
}
SEARCH_ALL = ["host", "event_id", "user", "src_ip", "dest", "log_source", "description", "cmd", "result", "log_id"]
ALERT_ORDER = {"bajo": 1, "medio": 2, "alto": 3, "critico": 4, "crítico": 4}
_LEVEL_ALIAS = {"critical": "critico", "high": "alto", "medium": "medio", "low": "bajo"}

TOKEN = re.compile(r"""\s*(?:
    (?P<lp>\() | (?P<rp>\)) |
    (?P<op>>=|<=|!=|=|:|>|<) |
    (?P<str>"(?:[^"]|"")*"|'(?:[^']|'')*') |
    (?P<word>[^\s()=:<>!"']+(?::[^\s()=<>"']+)*)
)""", re.X)


class QueryError(ValueError):
    def __init__(self, message: str, position: int = 0):
        super().__init__(message)
        self.message, self.position = message, position


@dataclass
class Tok:
    kind: str
    value: str
    pos: int


def tokenize(q: str):
    out, i = [], 0
    while i < len(q):
        if q[i:].strip() == "":
            break
        m = TOKEN.match(q, i)
        if not m or m.end() == i:
            raise QueryError(f"Carácter no válido: {q[i:].strip()[:1]}", i)
        kind = m.lastgroup
        v = m.group(kind)
        pos = m.start(kind)
        if kind == "str":
            v = v[1:-1].replace(v[0] * 2, v[0])
        if kind == "word":
            # "user:CORP\x": separa el operador cuando el campo es conocido
            head, sep, tail = v.partition(":")
            if sep and tail and (head.lower() in FIELDS or head.lower() in ALIASES):
                out += [Tok("word", head, pos), Tok("op", ":", pos + len(head)), Tok("word", tail, pos + len(head) + 1)]
                i = m.end()
                continue
            if sep and re.fullmatch(r"[A-Za-z_.@]+", head) and tail and tail[0] not in "\\/":
                raise QueryError(f"Campo desconocido: {head}.", pos)
        out.append(Tok(kind, v, pos))
        i = m.end()
    return out


class Parser:
    def __init__(self, q):
        self.t, self.i, self.q = tokenize(q), 0, q

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else None

    def next(self):
        tok = self.peek()
        self.i += 1
        return tok

    def _kw(self, *names):
        t = self.peek()
        return t is not None and t.kind == "word" and t.value.upper() in names

    def parse(self):
        if not self.t:
            return "1=1", []
        sql, params = self.or_()
        t = self.peek()
        if t is not None:
            raise QueryError(f"No se esperaba «{t.value}».", t.pos)
        return sql, params

    def or_(self):
        s, p = self.and_()
        while self._kw("OR"):
            self.next()
            s2, p2 = self.and_()
            s, p = f"({s} OR {s2})", p + p2
        return s, p

    def and_(self):
        s, p = self.not_()
        while True:
            if self._kw("AND"):
                self.next()
            elif self.peek() is not None and self.peek().kind in ("word", "str", "lp") and not self._kw("OR"):
                pass  # AND implícito entre términos
            else:
                return s, p
            s2, p2 = self.not_()
            s, p = f"({s} AND {s2})", p + p2

    def not_(self):
        if self._kw("NOT"):
            self.next()
            s, p = self.not_()
            return f"(NOT COALESCE({s},0))", p
        return self.atom()

    def atom(self):
        t = self.next()
        if t is None:
            raise QueryError("La consulta está incompleta.", len(self.q))
        if t.kind == "lp":
            s, p = self.or_()
            r = self.next()
            if r is None or r.kind != "rp":
                raise QueryError("Falta cerrar un paréntesis.", t.pos)
            return s, p
        if t.kind not in ("word", "str"):
            raise QueryError(f"No se esperaba «{t.value}».", t.pos)
        if t.kind == "word" and t.value.upper() in ("AND", "OR"):
            raise QueryError(f"Falta un término antes de {t.value.upper()}.", t.pos)
        n = self.peek()
        if t.kind == "word" and n is not None and n.kind == "op":
            return self.comparison(t)
        return self.free_text(t.value)

    def comparison(self, ftok):
        name = ftok.value.lower()
        name = ALIASES.get(name, name)
        if name not in FIELDS:
            raise QueryError(f"Campo desconocido: {ftok.value}.", ftok.pos)
        op = self.next()
        v = self.next()
        if v is None or v.kind not in ("word", "str"):
            raise QueryError(f"Falta el valor para {ftok.value}.", op.pos)
        col = FIELDS[name]
        if name == "alert":
            return self.alert(op, v)
        if op.value in (">", ">=", "<", "<="):
            if name == "event_id" and v.value.isdigit():
                return f"(CASE WHEN {col} GLOB '[0-9]*' THEN CAST({col} AS INTEGER) {op.value} ? ELSE 0 END)", [int(v.value)]
            return f"({col} {op.value} ?)", [v.value]
        if v.value == "*":
            return (f"({col} IS NOT NULL)", []) if op.value != "!=" else (f"({col} IS NULL)", [])
        sql, params = self.match(col, v.value, v.kind == "str")
        if name == "user" and "\\" not in v.value and "*" not in v.value and "?" not in v.value:
            # "user:admin" también encuentra "CORP\\admin"
            suffix = "%\\\\" + v.value.replace("%", "\\%").replace("_", "\\_")
            sql, params = f"({sql} OR {col} LIKE ? ESCAPE '\\')", params + [suffix]
        return (f"(NOT COALESCE({sql},0))", params) if op.value == "!=" else (sql, params)

    def alert(self, op, v):
        lv = _LEVEL_ALIAS.get(v.value.lower(), v.value.lower())
        if lv == "*":
            return "(alert_rank > 0)", []
        if lv not in ALERT_ORDER:
            raise QueryError("Severidad de alerta no válida. Usa bajo, medio, alto o crítico.", v.pos)
        o = {":": "=", "=": "="}.get(op.value, op.value)
        return f"(alert_rank {o} ?)", [ALERT_ORDER[lv]]

    @staticmethod
    def match(col, value, _quoted):
        if "*" in value or "?" in value:
            esc = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_").replace("*", "%").replace("?", "_")
            return f"({col} LIKE ? ESCAPE '\\')", [esc]
        return f"({col} = ? COLLATE NOCASE)", [value]

    @staticmethod
    def free_text(value):
        esc = "%" + value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_").replace("*", "%").replace("?", "_") + "%"
        parts = " OR ".join(f"{c} LIKE ? ESCAPE '\\'" for c in (FIELDS[f] for f in SEARCH_ALL))
        return f"({parts})", [esc] * len(SEARCH_ALL)


def compile_query(q: str):
    return Parser(q or "").parse()
