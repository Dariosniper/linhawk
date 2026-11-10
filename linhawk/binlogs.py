"""Binary Linux login records: wtmp / btmp / utmp (struct utmp, 384 bytes) and lastlog.

  wtmp  -> LOGIN / LOGOUT / BOOT / SHUTDOWN / RUNLEVEL  (who logged in, from where, when)
  btmp  -> FAILED_LOGIN                                 (bad logins, incl. SSH brute force)
  lastlog -> LASTLOG (last login per UID)
Also identifies other binary files so the skip report can say what they are."""

from __future__ import annotations

import ipaddress
import struct
from datetime import datetime, timezone, tzinfo
from pathlib import Path
from typing import Iterator

from .events import Event
from .fileio import open_binary, rotation_basename

UTMP = struct.Struct("<hxxi32s4s32s256shhiii16s20s")      # 384 bytes, glibc x86/x86_64/aarch64
LASTLOG = struct.Struct("<i32s256s")                        # 292 bytes
UT_TYPES = {0: "EMPTY", 1: "RUN_LVL", 2: "BOOT_TIME", 3: "NEW_TIME", 4: "OLD_TIME", 5: "INIT_PROCESS",
            6: "LOGIN_PROCESS", 7: "USER_PROCESS", 8: "DEAD_PROCESS", 9: "ACCOUNTING"}
TS_MIN, TS_MAX = 631152000, 4102444800                      # 1990 .. 2100


def _s(b: bytes) -> str:
    return b.split(b"\x00", 1)[0].decode("utf-8", "replace")


def _addr(raw: bytes) -> str:
    a = struct.unpack("<4I", raw)
    if not any(a):
        return ""
    if not any(a[1:]):
        return str(ipaddress.IPv4Address(raw[:4]))
    return str(ipaddress.IPv6Address(raw))


def looks_like_utmp(path: Path, head: bytes) -> bool:
    try:
        size = path.stat().st_size
    except OSError:
        return False
    if size == 0 or len(head) < UTMP.size or (size % UTMP.size and len(head) == size):
        return False
    good = 0
    for i in range(min(len(head) // UTMP.size, 8)):
        rec = UTMP.unpack_from(head, i * UTMP.size)
        if rec[0] not in UT_TYPES:
            return False
        if rec[0] and TS_MIN <= rec[10] <= TS_MAX:
            good += 1
    return good > 0


def kind_of_binary(path: Path, head: bytes) -> str:
    base = rotation_basename(path).lower()
    if head.startswith(b"LPKSHHRH"):
        return "journal"
    if base in ("wtmp", "btmp", "utmp", "wtmpx", "btmpx") or looks_like_utmp(path, head):
        return "utmp"
    if base == "lastlog":
        return "lastlog"
    if base in ("faillog", "tallylog"):
        return "faillog"
    if (base.startswith("sa") and base[2:].isdigit()) or head[:2] in (b"\x96\xd5", b"\xd5\x96"):
        return "sysstat"
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head.startswith(b"SQLite format 3"):
        return "sqlite"
    if head.startswith((b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a")):
        return "pcap"
    return "unknown"


BINARY_HINTS = {
    "journal": "systemd journal (binary): export it with `journalctl --file <file> -o json > x.json`",
    "faillog": "faillog/tallylog binary counters (no timeline value)",
    "sysstat": "sysstat sa binary: convert with `sadf -d <file>`",
    "elf": "executable, not a log",
    "sqlite": "SQLite database",
    "pcap": "packet capture (use Zeek/Wireshark)",
    "unknown": "unknown binary format",
}


class UtmpParser:
    def __init__(self, tz: tzinfo):
        self.tz = tz

    def parse(self, path: Path) -> Iterator[Event]:
        failed = "btmp" in rotation_basename(path).lower()
        with open_binary(path) as fh:
            n = 0
            while True:
                buf = fh.read(UTMP.size)
                if len(buf) < UTMP.size:
                    break
                n += 1
                (typ, pid, line, uid, user, host, _term, _exit, sess, sec, usec, addr, _) = UTMP.unpack(buf)
                if typ == 0 or not (TS_MIN <= sec <= TS_MAX):
                    continue
                ts = datetime.fromtimestamp(sec + usec / 1e6, tz=timezone.utc).astimezone(self.tz)
                user, line, host, ip = _s(user), _s(line), _s(host), _addr(addr)
                if failed:
                    etype = "FAILED_LOGIN"
                elif typ == 7:
                    etype = "LOGIN"
                elif typ == 8:
                    etype = "LOGOUT"
                elif typ == 2:
                    etype = "BOOT"
                elif typ == 1 and user == "shutdown":
                    etype = "SHUTDOWN"
                elif typ == 1:
                    etype = "RUNLEVEL"
                else:
                    etype = UT_TYPES.get(typ, str(typ))
                fields = {"EventType": etype, "UtType": UT_TYPES.get(typ, str(typ)), "User": user, "Tty": line,
                          "SrcHost": host, "SrcIP": ip or (host if _is_ip(host) else ""), "Pid": pid,
                          "Session": sess, "UtId": _s(uid)}
                fields = {k: v for k, v in fields.items() if v not in ("", None)}
                src = f" from {host}" if host else ""
                msg = f"{etype} {user} on {line}{src}".strip()
                svc = {"utmp", "btmp" if failed else "wtmp"}
                yield Event(ts, "-", "utmp", "login", msg, str(path), svc, None, fields, n)


class LastlogParser:
    MAX_SIZE = 256 * 1024 * 1024      # lastlog is sparse (indexed by UID): huge apparent sizes

    def __init__(self, tz: tzinfo):
        self.tz = tz

    def parse(self, path: Path) -> Iterator[Event]:
        if path.stat().st_size > self.MAX_SIZE:
            return
        with open_binary(path) as fh:
            uid = -1
            while True:
                buf = fh.read(LASTLOG.size)
                if len(buf) < LASTLOG.size:
                    break
                uid += 1
                sec, line, host = LASTLOG.unpack(buf)
                if not (TS_MIN <= sec <= TS_MAX):
                    continue
                ts = datetime.fromtimestamp(sec, tz=timezone.utc).astimezone(self.tz)
                host = _s(host)
                fields = {"EventType": "LASTLOG", "Uid": uid, "Tty": _s(line), "SrcHost": host,
                          "SrcIP": host if _is_ip(host) else ""}
                yield Event(ts, "-", "utmp", "lastlog", f"last login of uid {uid} on {_s(line)}"
                            + (f" from {host}" if host else ""), str(path), {"utmp", "lastlog"}, None,
                            {k: v for k, v in fields.items() if v not in ("", None)}, uid)


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False
