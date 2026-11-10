"""Generic parser for application logs that only share "a timestamp at the start of
the line": dracut, yum, dpkg, tuned, firewalld, cloud-init, anaconda-less app logs,
Tomcat, MySQL/MariaDB, custom applications...

At sniff time the dominant timestamp style of the file is chosen; lines that do not
start with it are treated as continuations (stack traces, multi-line messages)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone, tzinfo
from pathlib import Path
from typing import Callable, Iterator

from .enrich import enrich_message
from .events import Event
from .fileio import open_text, program_from_name, rotation_date

MON = "Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec"
DOW = "Mon|Tue|Wed|Thu|Fri|Sat|Sun"
MONTHS = {m: i for i, m in enumerate(MON.split("|"), 1)}

TZ_ABBR = {
    "UTC": 0, "GMT": 0, "Z": 0, "WET": 0, "WEST": 1, "BST": 1, "CET": 1, "CEST": 2, "MET": 1, "MEST": 2,
    "EET": 2, "EEST": 3, "MSK": 3, "EST": -5, "EDT": -4, "CST": -6, "CDT": -5, "MST": -7, "MDT": -6,
    "PST": -8, "PDT": -7, "AKST": -9, "AKDT": -8, "HST": -10, "JST": 9, "KST": 9, "AEST": 10, "AEDT": 11,
}


def _frac(s: str | None) -> int:
    return int((s or "0")[:6].ljust(6, "0"))


def _tz_from(token: str | None, default: tzinfo) -> tzinfo:
    if not token:
        return default
    token = token.strip()
    if token in TZ_ABBR:
        return timezone(timedelta(hours=TZ_ABBR[token]))
    m = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", token)
    if m:
        off = timedelta(hours=int(m[2]), minutes=int(m[3]))
        return timezone(off if m[1] == "+" else -off)
    return default


@dataclass
class TsStyle:
    name: str
    rx: re.Pattern
    build: Callable[[re.Match, tzinfo, "YearGuess"], datetime | None]


class YearGuess:
    """Year for timestamps without one: rotation date in the file name, else mtime,
    stepping back a year for dates in the future (Dec -> Jan)."""

    def __init__(self, path: Path, tz: tzinfo, year: int | None):
        self.year = year
        rd = rotation_date(path)
        if rd:
            self.ref = datetime(rd.year, rd.month, rd.day, 23, 59, 59, tzinfo=tz)
        else:
            try:
                self.ref = datetime.fromtimestamp(path.stat().st_mtime, tz=tz)
            except OSError:
                self.ref = datetime.now(tz=tz)

    def resolve(self, month, day, hh, mm, ss, us, tz) -> datetime | None:
        y = self.year or self.ref.year
        try:
            ts = datetime(y, month, day, hh, mm, ss, us, tzinfo=tz)
        except ValueError:
            return None
        if self.year is None and ts > self.ref + timedelta(days=2):
            ts = ts.replace(year=y - 1)
        return ts


def _iso(m, tz, _):
    try:
        ts = datetime(int(m["Y"]), int(m["M"]), int(m["D"]), int(m["h"]), int(m["m"]), int(m["s"]), _frac(m["f"]))
    except ValueError:
        return None
    return ts.replace(tzinfo=_tz_from(m["z"], tz))


def _ctime(m, tz, _):
    try:
        ts = datetime(int(m["Y"]), MONTHS[m["mon"]], int(m["D"]), int(m["h"]), int(m["m"]), int(m["s"]), _frac(m["f"]))
    except ValueError:
        return None
    return ts.replace(tzinfo=_tz_from(m["z"], tz))


def _clf(m, tz, _):
    try:
        ts = datetime(int(m["Y"]), MONTHS[m["mon"]], int(m["D"]), int(m["h"]), int(m["m"]), int(m["s"]), _frac(m["f"]))
    except ValueError:
        return None
    return ts.replace(tzinfo=_tz_from(m["z"], tz))


def _bsd(m, tz, yg: YearGuess):
    return yg.resolve(MONTHS[m["mon"]], int(m["D"]), int(m["h"]), int(m["m"]), int(m["s"]), _frac(m["f"]), tz)


def _mysql(m, tz):
    try:
        return datetime(2000 + int(m["y"]), int(m["M"]), int(m["D"]), int(m["h"]), int(m["m"]), int(m["s"]), tzinfo=tz)
    except ValueError:
        return None


def _epoch(m, tz, _):
    return datetime.fromtimestamp(float(m["e"]), tz=timezone.utc).astimezone(tz)


TZN = "|".join(sorted(TZ_ABBR, key=len, reverse=True))
T = r"(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})(?:[.,](?P<f>\d{1,9}))?"
LB, RB = r"^[\[(]?", r"[\])]?(?:\s*[|:-]?\s+|$)"
STYLES = [
    # 2015-10-13 10:58:37,123 / 2015-10-13T10:58:37.123+02:00 / 2015-10-13 10:58:37 UTC
    TsStyle("iso", re.compile(LB + r"(?P<Y>\d{4})-(?P<M>\d{2})-(?P<D>\d{2})(?:T| {1,2})" + T +
                              r"(?:\s?(?P<z>Z|[+-]\d{2}:?\d{2}|(?:" + TZN + r")(?=[\s\]])))?" + RB), _iso),
    # 2015/10/13 10:58:37
    TsStyle("slash", re.compile(LB + r"(?P<Y>\d{4})/(?P<M>\d{2})/(?P<D>\d{2})[ T-]" + T + r"(?P<z>)" + RB), _iso),
    # Tue Oct 13 10:58:37 CEST 2015 (date(1), dracut) / Tue Oct 13 10:58:37.123 2015 / Tue 13 Oct 2015 ...
    TsStyle("ctime", re.compile(LB + rf"(?:(?:{DOW}),? )?(?P<mon>{MON}) +(?P<D>\d{{1,2}}),? " + T +
                                r"(?: (?P<z>[A-Z]{2,5}|[+-]\d{4}))? (?P<Y>\d{4})" + RB), _ctime),
    # 13/Oct/2015:10:58:37 +0200
    TsStyle("clf", re.compile(LB + rf"(?P<D>\d{{2}})/(?P<mon>{MON})/(?P<Y>\d{{4}}):" + T + r"(?: (?P<z>[+-]\d{4}))?" + RB), _clf),
    # 13-Oct-2015 10:58:37.123 (Tomcat, BIND)
    TsStyle("dmy", re.compile(LB + rf"(?P<D>\d{{2}})-(?P<mon>{MON})-(?P<Y>\d{{4}}) " + T + r"(?P<z>)" + RB), _clf),
    # Oct 13 10:58:37 (no host, no year: yum.log, some app logs)
    TsStyle("bsd", re.compile(LB + rf"(?P<mon>{MON}) +(?P<D>\d{{1,2}}) " + T + RB), _bsd),
    # 151013 10:58:37 / 151013  9:58:37 (MySQL / MariaDB < 10.1)
    TsStyle("mysql", re.compile(r"^(?P<y>\d{2})(?P<M>\d{2})(?P<D>\d{2}) +(?P<h>\d{1,2}):(?P<m>\d{2}):(?P<s>\d{2})(?P<f>)(?P<z>)\s+"), lambda m, tz, _: _mysql(m, tz)),
    # 1444726717.123 (squid, some daemons) - 2001..2033
    TsStyle("epoch", re.compile(r"^\[?(?P<e>1\d{9}(?:\.\d+)?)\]?\s+"), _epoch),
]


# Same styles after a short prefix of 1-2 words: "update-alternatives 2026-10-01 10:00:00: ...",
# "E [09/Nov/2026:10:00:00 +0100] ..." (CUPS), "Start-Date: 2026-10-01  10:00:00" (apt history),
# "Log started: 2026-10-01  10:00:00" (apt term.log)
PREFIXED = [TsStyle(st.name + "+prefix",
                    re.compile(r"^(?P<pre>(?:[^\s\[\]]{1,40}\s+){1,2})" + st.rx.pattern[1:]), st.build)
            for st in STYLES if st.name != "epoch"]


def detect_style(lines: list[str]) -> TsStyle | None:
    """Dominant timestamp style among sample lines (needs >= 30% of them); styles with
    the timestamp at the very start of the line win over prefixed ones."""
    for candidates, ratio in ((STYLES, 0.3), (PREFIXED, 0.3)):
        best, best_n = None, 0
        for st in candidates:
            n = sum(1 for ln in lines if st.rx.match(ln))
            if n > best_n:
                best, best_n = st, n
        if best and best_n >= max(1, ratio * len(lines)):
            return best
    return None


CONT_PREFIXES = ("End-Date:", "Log ended:")
RE_PROG_PREFIX = re.compile(r"^(?P<prog>[A-Za-z][\w.-]{1,40})(?:\[(?P<pid>\d+)\])?:\s(?P<msg>.*)$")
MAX_MSG = 8000


class GenericParser:
    def __init__(self, tz: tzinfo, year: int | None = None):
        self.tz = tz
        self.year = year

    def parse(self, path: Path, style: TsStyle) -> Iterator[Event]:
        prog = program_from_name(path)
        yg = YearGuess(path, self.tz, self.year)
        pending: Event | None = None
        for n, line in enumerate(open_text(path), 1):
            m = style.rx.match(line)
            ts = style.build(m, self.tz, yg) if m else None
            if ts is not None and pending is not None and line.startswith(CONT_PREFIXES):
                ts = None                                    # "End-Date:" closes the apt block
            if ts is None:
                if pending is not None and line.strip() and len(pending.message) < MAX_MSG:
                    pending.message += "\n" + line          # continuation line
                continue
            if pending is not None:
                yield self._finish(pending)
            msg = line[m.end():]
            if "pre" in m.groupdict() and m["pre"]:
                msg = m["pre"].strip() + " " + msg          # keep "Start-Date:", "E", "update-alternatives"
            pending = Event(ts, "-", "applog", prog, msg, str(path), {"applog", prog.lower()}, None,
                            {"Program": prog, "LogFile": path.name}, n)
        if pending is not None:
            yield self._finish(pending)

    @staticmethod
    def _finish(ev: Event) -> Event:
        first = ev.message.split("\n", 1)[0]
        pm = RE_PROG_PREFIX.match(first)        # "sshd[123]: ..." inside an app log
        if pm and pm["prog"].lower() not in ("info", "warning", "error", "debug", "notice", "critical"):
            ev.fields["Process"] = pm["prog"]
            if pm["pid"]:
                ev.fields["Pid"] = int(pm["pid"])
        lvl = re.match(r"^\[?(TRACE|DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|ERR|CRIT(?:ICAL)?|FATAL|SEVERE)\]?\b", first, re.I)
        if lvl:
            ev.fields["Level"] = lvl.group(1).upper()
        ev.fields.update(enrich_message(ev.program, first))
        if ev.program.startswith("apt/"):
            ev.fields.update(apt_block(ev.message))
        return ev


RE_APT_ACTION = re.compile(r"^(Install|Reinstall|Upgrade|Downgrade|Remove|Purge): (.+)$", re.M)


def apt_block(msg: str) -> dict:
    """apt history.log block: Start-Date / Commandline / Requested-By / Install: ... / End-Date."""
    out = {}
    m = re.search(r"^Commandline: (.+)$", msg, re.M)
    if m:
        out["Command"] = m.group(1).strip()
    m = re.search(r"^Requested-By: (\S+)", msg, re.M)
    if m:
        out["User"] = m.group(1)
    acts = RE_APT_ACTION.findall(msg)
    if acts:
        out["EventType"] = "PACKAGE_CHANGE"
        out["Action"] = acts[0][0]
        out["Package"] = ", ".join(pk for _, pk in acts)[:4000]
    return out
