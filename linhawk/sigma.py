"""A compact Sigma rule engine (detection + correlation v2) for normalized Linux events."""

from __future__ import annotations

import base64
import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable, Iterable

import yaml

from .events import Event

LEVELS = ["informational", "low", "medium", "high", "critical"]
LEVEL_ABBR = {"informational": "info", "low": "low", "medium": "med", "high": "high", "critical": "crit"}
SUPPORTED_CATEGORIES = {"process_creation", "file_event", "webserver"}
SUPPORTED_PRODUCTS = {"linux", "apache", "nginx"}
KNOWN_SERVICES = {"auth", "sshd", "sudo", "syslog", "auditd", "cron", "vsftpd", "clamav", "guacamole",
                  "access", "apache", "nginx", "modsecurity", "weberror",
                  "applog", "utmp", "wtmp", "btmp", "lastlog"}


class RuleError(Exception):
    pass


# --------------------------------------------------------------------------- value matching

def _wildcard_to_regex(s: str) -> str:
    """Sigma wildcards: * and ?, backslash escapes them."""
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s) and s[i + 1] in "*?\\":
            out.append(re.escape(s[i + 1]))
            i += 2
            continue
        out.append(".*" if c == "*" else "." if c == "?" else re.escape(c))
        i += 1
    return "".join(out)


def _has_wildcard(s: str) -> bool:
    return bool(re.search(r"(?<!\\)[*?]", s))


def _to_str(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def _b64_variants(s: str, offset: bool) -> list[str]:
    data = s.encode()
    if not offset:
        return [base64.b64encode(data).decode().rstrip("=")]
    out = []
    for i in range(3):
        enc = base64.b64encode(b"\x00" * i + data).decode()
        start = (0, 2, 3)[i]
        end_trim = (0, 3, 2)[(len(data) + i) % 3]
        out.append(enc[start: len(enc) - end_trim if end_trim else None].rstrip("="))
    return out


def compile_value(value: Any, mods: list[str]) -> Callable[[Any], bool]:
    """Return predicate(field_value) for one Sigma value + modifiers."""
    cased = "cased" in mods
    flags = 0 if cased else re.IGNORECASE

    if "exists" in mods:
        want = bool(value)
        return lambda fv: (fv is not None and fv != "") == want

    if value is None:
        return lambda fv: fv is None or fv == ""

    if any(m in mods for m in ("gt", "gte", "lt", "lte")):
        op = next(m for m in mods if m in ("gt", "gte", "lt", "lte"))
        ref = float(value)

        def num(fv):
            try:
                x = float(fv)
            except (TypeError, ValueError):
                return False
            return {"gt": x > ref, "gte": x >= ref, "lt": x < ref, "lte": x <= ref}[op]
        return num

    if "cidr" in mods:
        net = ipaddress.ip_network(str(value), strict=False)

        def in_net(fv):
            try:
                return ipaddress.ip_address(str(fv)) in net
            except ValueError:
                return False
        return in_net

    sval = _to_str(value)

    if "re" in mods:
        rflags = 0
        if "i" in mods:
            rflags |= re.IGNORECASE
        if "m" in mods:
            rflags |= re.MULTILINE
        if "s" in mods:
            rflags |= re.DOTALL
        rx = re.compile(sval, rflags)
        return lambda fv: fv is not None and rx.search(_to_str(fv)) is not None

    pred = compile_strings([sval], mods)
    return lambda fv: fv is not None and pred(_to_str(fv), None)


def compile_strings(svals: list[str], mods: list[str]) -> Callable[[str, str | None], bool]:
    """One predicate for several plain string values (OR). Called as pred(s, s_lower):
    s_lower may be passed pre-computed (cached per event) or None."""
    cased = "cased" in mods
    variants = list(svals)
    if "windash" in mods:
        variants = list({w for v in variants for w in (v, v.replace("-", "/"), v.replace("/", "-"))})
    if "base64" in mods or "base64offset" in mods:
        variants = [b for v in variants for b in _b64_variants(v, "base64offset" in mods)]
        mods = [m for m in mods if m not in ("contains",)] + ["contains"]
    mode = next((m for m in ("contains", "startswith", "endswith") if m in mods), "equals")

    lits = [re.sub(r"\\([*?\\])", r"\1", v) for v in variants if not _has_wildcard(v)]
    if not cased:
        lits = [x.lower() for x in lits]
    wild = [_wildcard_to_regex(v) for v in variants if _has_wildcard(v)]
    rx = None
    if wild:
        body = "(?:" + "|".join(wild) + ")"
        body = {"contains": body, "startswith": "^" + body, "endswith": body + "$", "equals": "^" + body + "$"}[mode]
        rx = re.compile(body, (0 if cased else re.IGNORECASE) | re.DOTALL)

    if mode == "equals":
        litset = set(lits)
        test = lambda h: h in litset
    elif mode == "contains":
        test = lambda h: any(x in h for x in lits)
    elif mode == "startswith":
        tup = tuple(lits)
        test = lambda h: h.startswith(tup)
    else:
        tup = tuple(lits)
        test = lambda h: h.endswith(tup)

    def pred(s: str, sl: str | None) -> bool:
        h = s if cased else (sl if sl is not None else s.lower())
        if lits and test(h):
            return True
        return rx is not None and rx.search(s) is not None
    return pred


def _literal_parts(pattern: str) -> list[str]:
    """Literal chunks of a wildcard pattern (used as a cheap substring prefilter)."""
    parts = re.split(r"(?<!\\)[*?]", pattern)
    return [re.sub(r"\\([*?\\])", r"\1", x).lower() for x in parts if x]


def compile_keywords(values: list) -> Callable[["Event"], bool]:
    """Sigma keywords: case-insensitive substring match on the raw message.
    Wildcard keywords are only regex-checked if all their literal chunks are present."""
    plain, wild = [], []
    for v in map(_to_str, values):
        if _has_wildcard(v):
            wild.append((_literal_parts(v), re.compile(_wildcard_to_regex(v), re.IGNORECASE | re.DOTALL)))
        else:
            plain.append(re.sub(r"\\([*?\\])", r"\1", v).lower())

    def match(ev):
        h = ev.lower_message()
        if any(x in h for x in plain):
            return True
        for parts, rx in wild:
            if all(x in h for x in parts) and rx.search(ev.message):
                return True
        return False
    return match


# --------------------------------------------------------------------------- detection items

def _field_values(ev: Event, name: str) -> list:
    v = ev.get(name)
    if isinstance(v, list):
        return v or [None]
    return [v]


def compile_field(key: str, values: Any) -> Callable[[Event], bool]:
    parts = key.split("|")
    fname, mods = parts[0], [m.lower() for m in parts[1:]]
    vals = values if isinstance(values, list) else [values]
    if not vals:
        vals = [None]
    if "fieldref" in mods:
        refs = [str(v) for v in vals]
        return lambda ev: any(ev.get(fname) is not None and _to_str(ev.get(fname)) == _to_str(ev.get(r)) for r in refs)
    vmods = [m for m in mods if m != "all"]
    if not fname and not any(m in vmods for m in ("re", "startswith", "endswith", "contains")):
        vmods.append("contains")       # field-less values behave like keywords
    special = {"re", "cidr", "gt", "gte", "lt", "lte", "exists"}
    if fname and "all" not in mods and not special & set(vmods) and all(v is not None and v != "" for v in vals):
        # fast path: all values merged in one predicate, field strings lowered once per event
        pred = compile_strings([_to_str(v) for v in vals], vmods)
        return lambda ev: any(pred(s, sl) for s, sl in ev.str_values(fname))
    preds = [compile_value(v, vmods) for v in vals]
    combine = all if "all" in mods else any
    if not fname:
        return lambda ev: combine(p(ev.keyword_haystack()) for p in preds)
    return lambda ev: combine(any(p(fv) for fv in _field_values(ev, fname)) for p in preds)


def compile_search(obj: Any) -> Callable[[Event], bool]:
    if isinstance(obj, dict):
        preds = [compile_field(k, v) for k, v in obj.items()]
        return lambda ev: all(p(ev) for p in preds)
    if isinstance(obj, list):
        if all(isinstance(x, dict) for x in obj):
            subs = [compile_search(x) for x in obj]
            return lambda ev: any(s(ev) for s in subs)
        return compile_keywords([x for x in obj if not isinstance(x, dict)])
    if isinstance(obj, (str, int)):
        return compile_keywords([obj])
    raise RuleError(f"unsupported search identifier type: {type(obj).__name__}")


# --------------------------------------------------------------------------- condition parser

TOKEN_RX = re.compile(r"\s*(\(|\)|\b(?:and|or|not)\b|\b(?:1|all|any)\s+of\b|[\w*]+)", re.IGNORECASE)


def tokenize(cond: str) -> list[str]:
    tokens, pos = [], 0
    cond = cond.strip()
    while pos < len(cond):
        m = TOKEN_RX.match(cond, pos)
        if not m:
            raise RuleError(f"cannot parse condition near: {cond[pos:]!r}")
        tokens.append(re.sub(r"\s+", " ", m.group(1)))
        pos = m.end()
    return tokens


class ConditionParser:
    def __init__(self, tokens: list[str], searches: dict[str, Callable]):
        self.t, self.i, self.s = tokens, 0, searches

    def peek(self):
        return self.t[self.i].lower() if self.i < len(self.t) else None

    def take(self):
        tok = self.t[self.i]
        self.i += 1
        return tok

    def parse(self):
        node = self.or_expr()
        if self.i != len(self.t):
            raise RuleError(f"unexpected token {self.t[self.i]!r}")
        return node

    def or_expr(self):
        nodes = [self.and_expr()]
        while self.peek() == "or":
            self.take()
            nodes.append(self.and_expr())
        return nodes[0] if len(nodes) == 1 else (lambda ev, ns=nodes: any(n(ev) for n in ns))

    def and_expr(self):
        nodes = [self.not_expr()]
        while self.peek() == "and":
            self.take()
            nodes.append(self.not_expr())
        return nodes[0] if len(nodes) == 1 else (lambda ev, ns=nodes: all(n(ev) for n in ns))

    def not_expr(self):
        if self.peek() == "not":
            self.take()
            inner = self.not_expr()
            return lambda ev: not inner(ev)
        return self.primary()

    def primary(self):
        tok = self.peek()
        if tok is None:
            raise RuleError("unexpected end of condition")
        if tok == "(":
            self.take()
            node = self.or_expr()
            if self.peek() != ")":
                raise RuleError("missing ')'")
            self.take()
            return node
        if tok.endswith(" of"):
            quant = self.take().split()[0].lower()
            pat = self.take()
            names = list(self.s) if pat.lower() == "them" else [
                n for n in self.s if re.fullmatch(_wildcard_to_regex(pat), n)]
            if not names:
                raise RuleError(f"'{pat}' matches no search identifier")
            fns = [self.s[n] for n in names]
            if quant == "all":
                return lambda ev: all(f(ev) for f in fns)
            return lambda ev: any(f(ev) for f in fns)
        name = self.take()
        if name not in self.s:
            raise RuleError(f"unknown search identifier {name!r}")
        return self.s[name]


# --------------------------------------------------------------------------- rules

@dataclass
class SigmaRule:
    id: str
    title: str
    level: str
    status: str
    tags: list[str]
    logsource: dict
    path: str
    name: str | None = None
    description: str = ""
    author: str = ""
    falsepositives: list = field(default_factory=list)
    matcher: Callable[[Event], bool] = lambda ev: False
    suppressed: bool = False            # referenced by a correlation with generate: false

    def __post_init__(self):
        ls = self.logsource
        self.product = (ls.get("product") or "").lower() or None
        self.service = (ls.get("service") or "").lower() or None
        self.category = (ls.get("category") or "").lower() or None

    def logsource_ok(self, ev: Event) -> bool:
        if self.product and self.product not in ev.products:
            return False
        if self.category and ev.category != self.category:
            return False
        if not self.category and ev.category is not None:
            return False       # synthetic events only feed category rules
        if self.service and self.service not in ev.services:
            return False
        return True

    def match(self, ev: Event) -> bool:
        return self.logsource_ok(ev) and self.matcher(ev)


@dataclass
class CorrelationRule:
    id: str
    title: str
    level: str
    status: str
    tags: list[str]
    ctype: str
    rules: list[str]
    group_by: list[str]
    timespan: timedelta
    condition: dict
    path: str
    generate: bool = False
    description: str = ""
    name: str | None = None


def parse_timespan(s: str) -> timedelta:
    m = re.fullmatch(r"(\d+)\s*([smhdwMy])", str(s).strip())
    if not m:
        raise RuleError(f"bad timespan {s!r}")
    n, u = int(m[1]), m[2]
    return {"s": timedelta(seconds=n), "m": timedelta(minutes=n), "h": timedelta(hours=n),
            "d": timedelta(days=n), "w": timedelta(weeks=n), "M": timedelta(days=30 * n),
            "y": timedelta(days=365 * n)}[u]


def build_rule(doc: dict, path: str) -> SigmaRule:
    det = doc.get("detection")
    if not isinstance(det, dict) or "condition" not in det:
        raise RuleError("missing detection/condition")
    searches = {k: compile_search(v) for k, v in det.items() if k not in ("condition", "timeframe")}
    conds = det["condition"] if isinstance(det["condition"], list) else [det["condition"]]
    compiled = [ConditionParser(tokenize(str(c)), searches).parse() for c in conds]
    matcher = compiled[0] if len(compiled) == 1 else (lambda ev: any(c(ev) for c in compiled))
    level = str(doc.get("level", "medium")).lower()
    return SigmaRule(
        id=str(doc.get("id", "")), title=str(doc.get("title", "untitled")),
        level=level if level in LEVELS else "medium", status=str(doc.get("status", "")).lower(),
        tags=[str(t) for t in doc.get("tags", []) or []], logsource=doc.get("logsource", {}) or {},
        path=path, name=doc.get("name"), description=str(doc.get("description", "")).strip(),
        author=str(doc.get("author", "")), falsepositives=doc.get("falsepositives", []) or [],
        matcher=matcher)


def build_correlation(doc: dict, path: str) -> CorrelationRule:
    c = doc["correlation"]
    ctype = c.get("type")
    if ctype not in ("event_count", "value_count", "temporal", "temporal_ordered"):
        raise RuleError(f"unsupported correlation type {ctype!r}")
    rules = c.get("rules", [])
    rules = rules if isinstance(rules, list) else [rules]
    gb = c.get("group-by", []) or []
    level = str(doc.get("level", "high")).lower()
    return CorrelationRule(
        id=str(doc.get("id", "")), title=str(doc.get("title", "untitled correlation")),
        level=level if level in LEVELS else "high", status=str(doc.get("status", "")).lower(),
        tags=[str(t) for t in doc.get("tags", []) or []], ctype=ctype, rules=[str(r) for r in rules],
        group_by=gb if isinstance(gb, list) else [gb], timespan=parse_timespan(c.get("timespan", "1h")),
        condition=c.get("condition", {"gte": 1}) or {"gte": 1}, path=path,
        generate=bool(c.get("generate", False)), description=str(doc.get("description", "")).strip(),
        name=doc.get("name"))


@dataclass
class RuleSet:
    rules: list[SigmaRule] = field(default_factory=list)
    correlations: list[CorrelationRule] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)
    skipped: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def index(self):
        """Pre-bucket rules by service / category so each event only meets relevant rules."""
        self.by_service: dict[str, list[SigmaRule]] = defaultdict(list)
        self.by_category: dict[str, list[SigmaRule]] = defaultdict(list)
        self.generic: list[SigmaRule] = []
        for r in self.rules:
            if r.category:
                self.by_category[r.category].append(r)
            elif r.service:
                self.by_service[r.service].append(r)
            else:
                self.generic.append(r)

    def candidates(self, ev: Event) -> Iterable[SigmaRule]:
        if ev.category:
            yield from self.by_category.get(ev.category, ())
            return
        for s in ev.services:
            yield from self.by_service.get(s, ())
        yield from self.generic


def load_rules(paths: Iterable[str], min_level: str = "informational",
               exclude_status: set[str] | None = None) -> RuleSet:
    exclude_status = exclude_status if exclude_status is not None else {"deprecated", "unsupported"}
    rs = RuleSet()
    min_idx = LEVELS.index(min_level)
    files: list[Path] = []
    for p in paths:
        pp = Path(p)
        files.extend(sorted(pp.rglob("*.y*ml")) if pp.is_dir() else [pp])
    for f in files:
        try:
            docs = [d for d in yaml.safe_load_all(f.read_text(encoding="utf-8")) if isinstance(d, dict)]
        except (yaml.YAMLError, OSError, UnicodeDecodeError) as e:
            rs.errors.append((str(f), f"yaml: {e}"))
            continue
        for doc in docs:
            try:
                if "correlation" in doc:
                    cr = build_correlation(doc, str(f))
                    if cr.status in exclude_status:
                        rs.skipped[f"status:{cr.status}"] += 1
                    elif LEVELS.index(cr.level) < min_idx:
                        rs.skipped["level"] += 1
                    else:
                        rs.correlations.append(cr)
                    continue
                if "detection" not in doc:
                    rs.skipped["not-a-detection-rule"] += 1
                    continue
                ls = doc.get("logsource", {}) or {}
                product = (ls.get("product") or "").lower()
                if product and product not in SUPPORTED_PRODUCTS:
                    rs.skipped[f"product:{product}"] += 1
                    continue
                cat = (ls.get("category") or "").lower()
                service = (ls.get("service") or "").lower()
                if cat and cat not in SUPPORTED_CATEGORIES:
                    rs.skipped[f"category:{cat}"] += 1
                    continue
                if not product and not cat and service not in KNOWN_SERVICES:
                    rs.skipped["unsupported-logsource"] += 1
                    continue
                r = build_rule(doc, str(f))
                if r.status in exclude_status:
                    rs.skipped[f"status:{r.status}"] += 1
                    continue
                rs.rules.append(r)  # level filter applied at output time (correlation bases may be low)
            except (RuleError, re.error, ValueError, TypeError, KeyError) as e:
                rs.errors.append((str(f), str(e)))
    # wire correlations to base rules
    for cr in rs.correlations:
        for ref in cr.rules:
            for r in rs.rules:
                if ref in (r.id, r.name) and not cr.generate:
                    r.suppressed = True
    rs.index()
    return rs


# --------------------------------------------------------------------------- scanning

@dataclass
class Detection:
    event: Event
    rule_title: str
    level: str
    tags: list[str]
    rule_id: str
    rule_path: str
    details: dict[str, Any]
    correlation: bool = False


def _cmp(cond: dict, n: int) -> bool:
    ops = {"gt": n.__gt__, "gte": n.__ge__, "lt": n.__lt__, "lte": n.__le__, "eq": n.__eq__}
    return all(ops[k](int(v)) for k, v in cond.items() if k in ops)


def run_correlations(rs: RuleSet, base_hits: dict[str, list[tuple[Event, tuple]]]) -> list[Detection]:
    """base_hits[ref] = [(event, (rule_id, rule_name)), ...]"""
    out: list[Detection] = []
    for cr in rs.correlations:
        hits = []
        for ref in cr.rules:
            hits.extend(base_hits.get(ref, []))
        groups: dict[tuple, list[tuple[Event, SigmaRule]]] = defaultdict(list)
        for ev, r in hits:
            groups[tuple(_to_str(ev.get(g)) for g in cr.group_by)].append((ev, r))
        for gkey, evs in groups.items():
            evs.sort(key=lambda x: x[0].timestamp)
            i = 0
            while i < len(evs):
                start = evs[i][0].timestamp
                window = [x for x in evs[i:] if x[0].timestamp - start <= cr.timespan]
                fired, info = False, {}
                if cr.ctype == "event_count":
                    fired, info = _cmp(cr.condition, len(window)), {"Count": len(window)}
                elif cr.ctype == "value_count":
                    fld = cr.condition.get("field")
                    distinct = {_to_str(x[0].get(fld)) for x in window if x[0].get(fld) is not None}
                    fired, info = _cmp(cr.condition, len(distinct)), {"DistinctCount": len(distinct), "Field": fld}
                else:  # temporal: every referenced rule seen in the window
                    seen = {ref for x in window for ref in cr.rules if ref in x[1]}
                    fired = len(seen) == len(set(cr.rules))
                    if fired and cr.ctype == "temporal_ordered":
                        order = [next(i for i, ref in enumerate(cr.rules) if ref in x[1]) for x in window]
                        firsts = [order.index(k) for k in range(len(cr.rules))]
                        fired = firsts == sorted(firsts)
                    info = {"RulesSeen": len(seen)}
                if fired:
                    last = window[-1][0]
                    details = {**dict(zip(cr.group_by, gkey)), **info,
                               "FirstSeen": start.isoformat(), "LastSeen": last.timestamp.isoformat()}
                    out.append(Detection(last, cr.title, cr.level, cr.tags, cr.id, cr.path, details, True))
                    end = start + cr.timespan
                    while i < len(evs) and evs[i][0].timestamp <= end:
                        i += 1
                else:
                    i += 1
    return out
