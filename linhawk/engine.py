"""Scan events against a RuleSet and build Hayabusa-style detections."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable

from .events import Event
from .sigma import LEVELS, Detection, RuleSet, SigmaRule, run_correlations

DETAIL_ORDER = [
    "EventType", "User", "TargetUser", "SrcIP", "SrcHost", "SrcPort", "AuthMethod", "InvalidUser",
    "Action", "Package", "Level", "Process",
    "Command", "Pwd", "Tty", "Group", "TargetUid", "Shell", "Unit", "Module",
    "Image", "CommandLine", "ParentImage", "ProcessId", "ParentProcessId", "CurrentDirectory",
    "TargetFilename", "type", "syscall", "exe", "comm", "name", "key", "auid", "uid", "success",
]


def make_details(ev: Event) -> dict:
    d = {k: ev.fields[k] for k in DETAIL_ORDER if k in ev.fields and ev.fields[k] not in ("", None)}
    if ev.category == "process_creation":
        d = {k: d[k] for k in ("Image", "CommandLine", "ParentImage", "User", "ProcessId",
                                "ParentProcessId", "CurrentDirectory", "key") if k in d}
    if ev.category == "webserver":
        f = ev.fields
        d = {k: f[src] for k, src in (("SrcIP", "SrcIP"), ("User", "User"), ("Method", "Method"),
                                      ("Uri", "cs-uri"), ("Status", "Status"), ("Bytes", "sc-bytes"),
                                      ("VHost", "VHost"), ("UserAgent", "UserAgent"), ("Referer", "Referer"))
             if f.get(src) not in (None, "")}
        return d
    if ev.channel == "weberror":
        d = {k: ev.fields[k] for k in ("Level", "Module", "ErrorCode", "SrcIP", "VHost", "Request")
             if ev.fields.get(k)}
        d["Msg"] = ev.message[:300]
        return d
    if not d or (len(d) == 1 and "type" in d) or ("EventType" not in d and ev.channel != "auditd"):
        d["Msg"] = ev.message[:300]
    return d


@dataclass
class ScanStats:
    events: int = 0
    first: datetime | None = None
    last: datetime | None = None
    by_channel: Counter = field(default_factory=Counter)
    by_host: Counter = field(default_factory=Counter)
    files: set = field(default_factory=set)
    rule_errors: int = 0


def in_range(ev: Event, start: datetime | None, end: datetime | None) -> bool:
    return (start is None or ev.timestamp >= start) and (end is None or ev.timestamp <= end)


def _accumulate(stats: ScanStats, ev: Event):
    stats.events += 1
    stats.by_channel[ev.channel] += 1
    stats.by_host[ev.host] += 1
    stats.files.add(ev.source_file)
    if stats.first is None or ev.timestamp < stats.first:
        stats.first = ev.timestamp
    if stats.last is None or ev.timestamp > stats.last:
        stats.last = ev.timestamp


def scan_partial(events: Iterable[Event], rs: RuleSet, min_level: str = "informational",
                 start: datetime | None = None, end: datetime | None = None):
    """Match events against single-event rules. Returns (detections, base_hits, stats);
    base_hits[ref] = [(event, (rule_id, rule_name)), ...] feeds the correlation stage."""
    stats = ScanStats()
    detections: list[Detection] = []
    base_hits: dict[str, list[tuple[Event, tuple]]] = defaultdict(list)
    correlated_refs = {ref for cr in rs.correlations for ref in cr.rules}
    min_idx = LEVELS.index(min_level)
    for ev in events:
        if not in_range(ev, start, end):
            continue
        _accumulate(stats, ev)
        for r in rs.candidates(ev):
            try:
                hit = r.match(ev)
            except Exception:  # a buggy rule must never stop the scan
                stats.rule_errors += 1
                continue
            if not hit:
                continue
            for ref in (r.id, r.name):
                if ref and ref in correlated_refs:
                    base_hits[ref].append((ev, (r.id, r.name)))
            if not r.suppressed and LEVELS.index(r.level) >= min_idx:
                detections.append(Detection(ev, r.title, r.level, r.tags, r.id, r.path, make_details(ev)))
    return detections, base_hits, stats


def finalize(rs: RuleSet, detections: list[Detection], base_hits, min_level: str) -> list[Detection]:
    min_idx = LEVELS.index(min_level)
    for d in run_correlations(rs, base_hits):
        if LEVELS.index(d.level) >= min_idx:
            detections.append(d)
    detections.sort(key=lambda d: (d.event.timestamp, -LEVELS.index(d.level)))
    return detections


def scan(events: Iterable[Event], rs: RuleSet, min_level: str = "informational",
         start: datetime | None = None, end: datetime | None = None) -> tuple[list[Detection], ScanStats]:
    dets, hits, stats = scan_partial(events, rs, min_level, start, end)
    return finalize(rs, dets, hits, min_level), stats


# --------------------------------------------------------------------------- parallel (one file per worker)

_W: dict = {}


def _worker_init(rule_paths, min_level, exclude_status, opts):
    from .sigma import load_rules
    _W["rs"] = load_rules(rule_paths, min_level, exclude_status)
    _W["opts"] = opts


def _strip(ev: Event) -> Event:
    for k in ("_sv", "_lm", "_lk"):
        ev.__dict__.pop(k, None)
    return ev


def _worker_scan(path: str):
    from .parsers import load_events
    o = _W["opts"]
    skipped: list = []
    evs = load_events([path], o["tz"], o["year"], on_skip=lambda f, why, sample="": skipped.append((str(f), why, sample)))
    if o["host"]:
        evs = (_fill(e, o["host"]) for e in evs)
    dets, hits, stats = scan_partial(evs, _W["rs"], o["min_level"], o["start"], o["end"])
    for d in dets:
        _strip(d.event)
    for lst in hits.values():
        for ev, _ in lst:
            _strip(ev)
    return dets, dict(hits), stats, skipped


def _fill(ev: Event, host: str) -> Event:
    if ev.host == "-":
        ev.host = host
    return ev


def merge_stats(a: ScanStats, b: ScanStats) -> ScanStats:
    a.events += b.events
    a.by_channel.update(b.by_channel)
    a.by_host.update(b.by_host)
    a.files |= b.files
    a.rule_errors += b.rule_errors
    for t in (b.first,):
        if t and (a.first is None or t < a.first):
            a.first = t
    for t in (b.last,):
        if t and (a.last is None or t > a.last):
            a.last = t
    return a


def scan_files_parallel(files: list[str], rs: RuleSet, rule_paths: list[str], exclude_status: set,
                        opts: dict, workers: int):
    """Hayabusa-style multi-core scan: each worker parses and matches whole files;
    correlations run afterwards on the merged base hits (so they work across files)."""
    from concurrent.futures import ProcessPoolExecutor
    detections: list[Detection] = []
    base_hits: dict = defaultdict(list)
    stats, skipped = ScanStats(), []
    # biggest files first for better load balancing
    files = sorted(files, key=lambda f: -_size(f))
    with ProcessPoolExecutor(max_workers=workers, initializer=_worker_init,
                             initargs=(rule_paths, opts["min_level"], exclude_status, opts)) as ex:
        for dets, hits, st, sk in ex.map(_worker_scan, files):
            detections.extend(dets)
            for k, v in hits.items():
                base_hits[k].extend(v)
            merge_stats(stats, st)
            skipped.extend(sk)
    return finalize(rs, detections, base_hits, opts["min_level"]), stats, skipped


def _size(f: str) -> int:
    import os
    try:
        return os.path.getsize(f)
    except OSError:
        return 0
