"""Parsers for Linux log sources -> normalized Event objects.

Supported inputs
  * syslog-style text logs: /var/log/auth.log, secure, syslog, messages, cron, ...
    (RFC3164 "Nov  6 10:00:00 host prog[pid]: msg" and RFC3339/ISO timestamps)
  * auditd: /var/log/audit/audit.log (raw or "enriched" format)
  * journald: `journalctl -o json` exports, or binary *.journal files if journalctl exists
  * web servers: Apache / nginx access logs (common, combined, vhost_combined, JSON) and error logs
  * any of the above gzip-compressed (.gz), e.g. rotated logs
"""

from __future__ import annotations

import gzip
import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
from typing import Iterable, Iterator

from .binlogs import BINARY_HINTS, LastlogParser, UtmpParser, kind_of_binary
from .enrich import enrich_message, services_for_program
from .events import Event
from .fileio import open_text, read_head, rotation_date
from .genericlog import GenericParser, detect_style
from .webparsers import (WebAccessParser, WebErrorParser, looks_like_access, looks_like_access_json,
                         looks_like_error)

# --------------------------------------------------------------------------- helpers

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

RE_RFC3164 = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<rest>.*)$")
RE_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<host>\S+)\s+(?P<rest>.*)$")
RE_PROG = re.compile(r"^(?P<prog>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$")

RE_AUDIT_HDR = re.compile(r"(?:node=(?P<node>\S+)\s+)?type=(?P<type>\S+)\s+msg=audit\((?P<ts>\d+\.\d+):(?P<serial>\d+)\):\s?(?P<body>.*)$")
RE_AUDIT_KV = re.compile(r"""(\w[\w-]*)=("(?:[^"\\]|\\.)*"|'[^']*'|\S*)""")
RE_HEX = re.compile(r"^[0-9A-Fa-f]+$")


class Sniff:
    """Result of format detection: fmt is None when the file is skipped (reason says why)."""

    def __init__(self, fmt: str | None, reason: str = "", style=None, sample: str = ""):
        self.fmt, self.reason, self.style, self.sample = fmt, reason, style, sample


def _is_binary(head: bytes) -> bool:
    if not head:
        return False
    if b"\x00" in head[:4096]:
        return True
    ctrl = sum(1 for c in head[:4096] if c < 9 or 13 < c < 32)
    return ctrl > len(head[:4096]) * 0.1


def sniff_format(path: Path) -> Sniff:
    try:
        if path.stat().st_size == 0:
            return Sniff(None, "empty")
    except OSError as e:
        return Sniff(None, f"unreadable: {e}")
    head = read_head(path)
    if not head:
        return Sniff(None, "empty (after decompression) or unreadable")
    if _is_binary(head):
        kind = kind_of_binary(path, head)
        if kind == "utmp":
            return Sniff("utmp")
        if kind == "lastlog":
            return Sniff("lastlog")
        if kind == "journal":
            return Sniff("journal-binary")
        return Sniff(None, f"binary: {BINARY_HINTS[kind]}")

    text = head.decode("utf-8", "replace")
    raw_lines = text.splitlines()
    if len(head) == 65536 and raw_lines:
        raw_lines = raw_lines[:-1]                  # last line may be truncated
    lines = [ln for ln in raw_lines if ln.strip()][:50]
    if not lines:
        return Sniff(None, "empty (whitespace only)")
    sample = lines[0][:160]
    half = len(lines) / 2
    if lines[0].lstrip().startswith("{"):
        try:
            first = json.loads(lines[0])
        except json.JSONDecodeError:
            first = None
        if isinstance(first, dict) and "__REALTIME_TIMESTAMP" in first:
            return Sniff("journald-json")
        if isinstance(first, dict) and looks_like_access_json(first):
            return Sniff("web-access-json")
    if sum(1 for ln in lines if "msg=audit(" in ln) >= half:
        return Sniff("auditd")
    if sum(1 for ln in lines if looks_like_access(ln)) >= half:
        return Sniff("web-access")
    if sum(1 for ln in lines if looks_like_error(ln)) >= half:
        return Sniff("web-error")
    if sum(1 for ln in lines if (RE_RFC3164.match(ln) or RE_ISO.match(ln)) and _syslog_shape(ln)) >= half:
        return Sniff("syslog")
    style = detect_style(lines)
    if style:
        return Sniff("generic", style=style)
    if re.match(r"^\[\s*\d+\.\d+\]", lines[0]):
        return Sniff(None, "kernel ring buffer (dmesg): only seconds since boot, no wall-clock time", sample=sample)
    if sum(1 for ln in lines if RE_TIME_ONLY.match(ln)) >= half:
        return Sniff(None, "timestamps without a date (time of day only, e.g. anaconda)", sample=sample)
    return Sniff(None, "text without recognizable timestamps", sample=sample)


def _syslog_shape(line: str) -> bool:
    """RFC3164/ISO line whose 2nd token is a host and 3rd a 'prog[pid]:' tag."""
    m = RE_RFC3164.match(line) or RE_ISO.match(line)
    if not m or not RE_PROG.match(m["rest"]) or m["host"].endswith(":"):
        return False
    if m["host"].upper().strip("[]") in LEVEL_WORDS or m["host"] in ("-", "|"):
        return False                                    # "2015-10-13 10:00:00 INFO x: ..." = app log
    if "ts" in m.groupdict() and ("," in m["ts"] or " " in m["ts"]):
        return False        # "10:00:00,123" or "2026-10-20 11:02:15" (no T) = application log (dpkg, Python, Java)
    return True


LEVEL_WORDS = {"TRACE", "DEBUG", "INFO", "NOTICE", "WARN", "WARNING", "ERROR", "ERR", "CRIT", "CRITICAL",
               "FATAL", "SEVERE", "ALERT", "EMERG"}
RE_TIME_ONLY = re.compile(r"^\[?\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\]?\s")


def iter_files(paths: Iterable[str]) -> Iterator[Path]:
    for p in paths:
        path = Path(p)
        if path.is_dir():
            for f in sorted(path.rglob("*")):
                if f.is_file():
                    yield f
        elif path.is_file():
            yield path


def _hex_decode(val: str) -> str:
    try:
        return bytes.fromhex(val).replace(b"\x00", b" ").decode("utf-8", "replace").strip()
    except ValueError:
        return val


def _unquote(val: str) -> str:
    if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
        return val[1:-1]
    return val


# --------------------------------------------------------------------------- syslog

class SyslogParser:
    def __init__(self, tz: tzinfo, year: int | None = None):
        self.tz = tz
        self.year = year

    def parse(self, path: Path) -> Iterator[Event]:
        # RFC3164 has no year: use --year, otherwise the file mtime year, and step back
        # one year for entries that would land in the future (Dec -> Jan rotation).
        rd = rotation_date(path)     # logrotate dateext: messages-20151013 ends on that day
        if rd:
            ref = datetime(rd.year, rd.month, rd.day, 23, 59, 59, tzinfo=self.tz)
        else:
            try:
                ref = datetime.fromtimestamp(path.stat().st_mtime, tz=self.tz)
            except OSError:
                ref = datetime.now(tz=self.tz)
        base_year = self.year or ref.year
        file_hint = path.name.lower()
        auth_file = any(k in file_hint for k in ("auth", "secure"))

        for n, line in enumerate(open_text(path), 1):
            if not line.strip():
                continue
            m = RE_RFC3164.match(line)
            if m:
                hh, mm, ss = (int(x) for x in m["time"].split(":"))
                try:
                    ts = datetime(base_year, MONTHS[m["mon"]], int(m["day"]), hh, mm, ss, tzinfo=self.tz)
                except (KeyError, ValueError):
                    continue
                if self.year is None and ts > ref + timedelta(days=2):
                    ts = ts.replace(year=base_year - 1)
            else:
                m = RE_ISO.match(line)
                if not m:
                    continue
                ts = _parse_iso(m["ts"], self.tz)
                if ts is None:
                    continue
            yield self._build(ts, m["host"], m["rest"], line, path, n, auth_file)

    def _build(self, ts, host, rest, raw, path, n, auth_file) -> Event:
        pm = RE_PROG.match(rest)
        if pm:
            prog, pid, msg = pm["prog"], pm["pid"], pm["msg"]
        else:
            prog, pid, msg = "-", None, rest
        services = {"syslog"} | services_for_program(prog)
        if auth_file:
            services.add("auth")
        fields = {"Program": prog, "Hostname": host}
        if pid:
            fields["Pid"] = int(pid)
        fields.update(enrich_message(prog, msg))
        return Event(ts, host, "syslog", prog, msg, str(path), services, None, fields, n)


def _parse_iso(s: str, tz: tzinfo) -> datetime | None:
    s = s.replace(",", ".").replace(" ", "T", 1)
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    # Python handles at most 6 fractional digits
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)
    try:
        ts = datetime.fromisoformat(s)
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=tz)


# --------------------------------------------------------------------------- auditd

def parse_audit_line(line: str) -> dict | None:
    raw = line.split("\x1d", 1)          # enriched format: raw \x1d interpreted
    m = RE_AUDIT_HDR.search(raw[0])
    if not m:
        return None
    rec = {"type": m["type"], "_ts": float(m["ts"]), "_serial": int(m["serial"])}
    if m["node"]:
        rec["node"] = m["node"]
    body = m["body"]
    # USER_* records embed a msg='...' with the real key/values
    inner = re.search(r"msg='(.*)'", body)
    if inner:
        body = body[: inner.start()] + " " + inner.group(1)
    for k, v in RE_AUDIT_KV.findall(body):
        if v.startswith('"'):
            rec[k] = _unquote(v)
        elif k in ("proctitle",) or (re.fullmatch(r"a\d+", k) and rec["type"] == "EXECVE"):
            rec[k] = _hex_decode(v) if RE_HEX.match(v) and len(v) % 2 == 0 and len(v) > 2 else v
        else:
            rec[k] = _unquote(v)
    if len(raw) > 1:                     # interpreted values, e.g. UID="root"
        for k, v in RE_AUDIT_KV.findall(raw[1]):
            rec[k] = _unquote(v)
    return rec


class AuditdParser:
    """Emits one event per audit record (enriched with its group context, as most
    Sigma auditd rules expect) plus a synthetic `process_creation` event per execve."""

    CONTEXT_KEYS = ("exe", "comm", "pid", "ppid", "uid", "auid", "euid", "ses", "tty",
                    "key", "syscall", "success", "cwd", "proctitle", "UID", "AUID", "SYSCALL")

    def __init__(self, tz: tzinfo):
        self.tz = tz

    def parse(self, path: Path) -> Iterator[Event]:
        groups: dict[tuple, list] = {}
        pid_exe: dict[str, str] = {}
        for n, line in enumerate(open_text(path), 1):
            rec = parse_audit_line(line)
            if not rec:
                continue
            key = (rec["_ts"], rec["_serial"])
            if rec["type"] == "EOE":
                if key in groups:
                    yield from self._emit(groups.pop(key), path, pid_exe)
                continue
            groups.setdefault(key, []).append((n, line, rec))
            # flush old groups that never got an EOE (records are near each other in time)
            if len(groups) > 500:
                for k in sorted(groups)[:250]:
                    yield from self._emit(groups.pop(k), path, pid_exe)
        for k in sorted(groups):
            yield from self._emit(groups[k], path, pid_exe)

    def _emit(self, group, path, pid_exe) -> Iterator[Event]:
        ctx: dict = {}
        for _, _, rec in group:
            for k in self.CONTEXT_KEYS:
                if k in rec and k not in ctx:
                    ctx[k] = rec[k]
        ts = datetime.fromtimestamp(group[0][2]["_ts"], tz=timezone.utc).astimezone(self.tz)
        host = group[0][2].get("node", "-")
        for n, line, rec in group:
            fields = {k: v for k, v in rec.items() if not k.startswith("_")}
            for k, v in ctx.items():
                fields.setdefault(k, v)
            fields["serial"] = rec["_serial"]
            yield Event(ts, host, "auditd", rec.get("comm", ctx.get("comm", "auditd")), line,
                        str(path), {"auditd"}, None, fields, n)

        types = {rec["type"] for _, _, rec in group}
        # synthetic file_event for files created (PATH nametype=CREATE)
        for n, line, rec in group:
            if rec["type"] == "PATH" and rec.get("nametype") == "CREATE" and rec.get("name"):
                name = rec["name"]
                if not name.startswith("/") and ctx.get("cwd"):
                    name = ctx["cwd"].rstrip("/") + "/" + name
                fields = {"TargetFilename": name, "Image": ctx.get("exe", ""),
                          "User": ctx.get("UID", ctx.get("uid", "")), "ProcessId": ctx.get("pid", ""),
                          "key": ctx.get("key", ""), "EventType": "FILE_CREATE"}
                yield Event(ts, host, "auditd", ctx.get("comm", "-"), f"file create: {name}",
                            str(path), {"auditd"}, "file_event", fields, n)
        pid, exe = str(ctx.get("pid", "")), ctx.get("exe", "")
        if pid and exe:                  # remember pid -> image to resolve ParentImage
            pid_exe[pid] = exe
        if "EXECVE" in types:
            ex = next(rec for _, _, rec in group if rec["type"] == "EXECVE")
            try:
                argc = int(ex.get("argc", 0))
            except ValueError:
                argc = 0
            args = [ex.get(f"a{i}", "") for i in range(argc)] or [ctx.get("proctitle", "")]
            cmdline = " ".join(a for a in args if a)
            ppid = str(ctx.get("ppid", ""))
            fields = {
                "Image": ctx.get("exe", ""),
                "CommandLine": cmdline,
                "ProcessId": ctx.get("pid", ""),
                "ParentProcessId": ppid,
                "ParentImage": pid_exe.get(ppid, ""),
                "User": ctx.get("UID", ctx.get("uid", "")),
                "LogonId": ctx.get("ses", ""),
                "CurrentDirectory": ctx.get("cwd", ""),
                "auid": ctx.get("AUID", ctx.get("auid", "")),
                "key": ctx.get("key", ""),
                "EventType": "PROCESS_EXEC",
            }
            n, line, _ = group[0]
            yield Event(ts, host, "auditd", ctx.get("comm", "-"), f"exec: {cmdline}", str(path),
                        {"auditd"}, "process_creation", fields, n)


# --------------------------------------------------------------------------- journald

class JournaldParser:
    def __init__(self, tz: tzinfo):
        self.tz = tz

    def lines(self, path: Path, binary: bool) -> Iterator[str]:
        if not binary:
            yield from open_text(path)
            return
        jc = shutil.which("journalctl")
        if not jc:
            raise RuntimeError(f"{path}: binary journal requires journalctl "
                               f"(or export with: journalctl --file {path} -o json)")
        # --all: export long / non-printable fields instead of null
        proc = subprocess.Popen([jc, "--file", str(path), "-o", "json", "--all", "--no-pager"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace")
        assert proc.stdout and proc.stderr
        n = 0
        for ln in proc.stdout:
            n += 1
            yield ln.rstrip("\n")
        proc.wait()
        if n == 0 and proc.returncode:
            raise RuntimeError(f"journalctl could not read it: {proc.stderr.read().strip()[:200]}")

    def parse(self, path: Path, binary: bool = False) -> Iterator[Event]:
        for n, line in enumerate(self.lines(path, binary), 1):
            try:
                j = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(j, dict):
                continue
            try:
                ts = datetime.fromtimestamp(int(jval(j.get("__REALTIME_TIMESTAMP"))) / 1e6,
                                            tz=timezone.utc).astimezone(self.tz)
            except (TypeError, ValueError, OverflowError, OSError):
                continue
            msg = jval(j.get("MESSAGE"))
            prog = jfirst(j.get("SYSLOG_IDENTIFIER")) or jfirst(j.get("_COMM")) or "-"
            host = jfirst(j.get("_HOSTNAME")) or "-"
            services = {"syslog"} | services_for_program(prog)
            fields = {k.lstrip("_"): jval(v) for k, v in j.items() if not k.startswith("__") and k != "MESSAGE"}
            fields["Program"] = prog
            pid = jval(j.get("_PID"))
            if pid:
                fields["Pid"] = pid
            fields.update(enrich_message(prog, msg))
            if jval(j.get("_TRANSPORT")) == "audit":
                rec = parse_audit_line(f"type={jval(j.get('_AUDIT_TYPE_NAME')) or 'UNKNOWN'} "
                                       f"msg=audit({ts.timestamp():.3f}:0): {msg}")
                if rec:
                    fields.update({k: v for k, v in rec.items() if not k.startswith("_")})
                    services = {"auditd"}
            yield Event(ts, host, "journald", prog, msg, str(path), services, None, fields, n)


def jfirst(v) -> str:
    """First value of a possibly repeated field (identifiers, hostnames)."""
    if isinstance(v, list) and v and not all(isinstance(x, int) for x in v):
        v = v[0]
    return jval(v)


def jval(v) -> str:
    """Normalize a journalctl JSON value to text: null (field too long / binary without
    --all), byte arrays (non-UTF-8 data), lists of values (field repeated in one entry)."""
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    if isinstance(v, list):
        if v and all(isinstance(x, int) and 0 <= x < 256 for x in v):
            return bytes(v).decode("utf-8", "replace")
        return "\n".join(jval(x) for x in v)
    return str(v)


# --------------------------------------------------------------------------- dispatcher

def load_events(paths: Iterable[str], tz: tzinfo, year: int | None = None,
                on_skip=None) -> Iterator[Event]:
    """on_skip(path, reason, sample) is called for every file that yields no events."""
    sp, ap, jp = SyslogParser(tz, year), AuditdParser(tz), JournaldParser(tz)
    wa, we, gp = WebAccessParser(tz), WebErrorParser(tz), GenericParser(tz, year)
    up, lp = UtmpParser(tz), LastlogParser(tz)
    counter = [0]
    for f in iter_files(paths):
        sn = sniff_format(f)
        fmt = sn.fmt
        if fmt is None:
            if on_skip:
                on_skip(f, sn.reason, sn.sample)
            continue
        before = counter[0]
        try:
            for ev in _parse_one(fmt, f, sn, sp, ap, jp, wa, we, gp, up, lp):
                counter[0] += 1
                yield ev
        except Exception as e:  # a malformed file must never stop the whole scan
            if on_skip:
                if fmt == "journal-binary" and isinstance(e, RuntimeError):
                    why = "binary: " + BINARY_HINTS["journal"] + (f" ({e})" if "journalctl could" in str(e) else "")
                else:
                    why = f"parser error after {counter[0] - before} events ({fmt}): {type(e).__name__}: {e}"
                on_skip(f, why, "")
            continue
        if counter[0] == before and on_skip:
            on_skip(f, f"recognized as {fmt} but no event could be parsed", sn.sample)


def _parse_one(fmt, f, sn, sp, ap, jp, wa, we, gp, up, lp):
    if fmt == "syslog":
        yield from sp.parse(f)
    elif fmt == "auditd":
        yield from ap.parse(f)
    elif fmt == "journald-json":
        yield from jp.parse(f)
    elif fmt == "web-access":
        yield from wa.parse(open_text(f), f)
    elif fmt == "web-access-json":
        yield from wa.parse_json(open_text(f), f)
    elif fmt == "web-error":
        yield from we.parse(open_text(f), f)
    elif fmt == "generic":
        yield from gp.parse(f, sn.style)
    elif fmt == "utmp":
        yield from up.parse(f)
    elif fmt == "lastlog":
        yield from lp.parse(f)
    elif fmt == "journal-binary":
        yield from jp.parse(f, binary=True)
