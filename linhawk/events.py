"""Common, normalized event model shared by all parsers."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class Event:
    timestamp: datetime            # always timezone-aware
    host: str                      # hostname from the log, "-" if unknown
    channel: str                   # source family: "syslog", "auditd", "journald"
    program: str                   # emitting program (sshd, sudo, kernel, ...)
    message: str                   # human readable message / raw record
    source_file: str
    services: set[str] = field(default_factory=set)   # Sigma logsource.service values
    category: str | None = None                       # Sigma logsource.category
    fields: dict[str, Any] = field(default_factory=dict)
    line_no: int = 0
    products: set[str] = field(default_factory=lambda: {"linux"})  # Sigma logsource.product

    def get(self, name: str) -> Any:
        """Field lookup: exact name, then case-insensitive, then core attributes."""
        if name in self.fields:
            return self.fields[name]
        lname = name.lower()
        lk = self.__dict__.get("_lk")
        if lk is None or len(lk) != len(self.fields):
            lk = self.__dict__["_lk"] = {k.lower(): k for k in self.fields}
        if lname in lk:
            return self.fields[lk[lname]]
        core = {
            "message": self.message, "msg": self.message, "host": self.host,
            "hostname": self.host, "program": self.program, "channel": self.channel,
        }
        return core.get(lname)

    def str_values(self, name: str) -> list[tuple[str, str]]:
        """(value, lowercased value) pairs of a field, cached per event; [] if missing."""
        cache = self.__dict__.setdefault("_sv", {})
        out = cache.get(name)
        if out is None:
            v = self.get(name)
            vals = v if isinstance(v, list) else [v]
            out = []
            for x in vals:
                if x is None or x == "":
                    continue
                sx = ("true" if x else "false") if isinstance(x, bool) else str(x)
                out.append((sx, sx.lower()))
            cache[name] = out
        return out

    def lower_message(self) -> str:
        lm = self.__dict__.get("_lm")
        if lm is None:
            lm = self.__dict__["_lm"] = self.message.lower()
        return lm

    def keyword_haystack(self) -> str:
        """Text searched by Sigma `keywords` (whole raw message + values)."""
        return self.message

    def as_dict(self) -> dict[str, Any]:
        return {
            "Timestamp": self.timestamp.isoformat(),
            "Host": self.host,
            "Channel": self.channel,
            "Program": self.program,
            "Category": self.category,
            "Services": sorted(self.services),
            "Message": self.message,
            "Fields": self.fields,
            "SourceFile": self.source_file,
            "Line": self.line_no,
        }
