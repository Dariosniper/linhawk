"""Timeline writers (CSV / JSON / JSONL) and terminal summaries."""

from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path, PurePath
from typing import IO, Iterable

from .sigma import LEVEL_ABBR, LEVELS, Detection

TACTICS = {
    "reconnaissance": "Recon", "resource-development": "ResDev", "initial-access": "InitAccess",
    "execution": "Exec", "persistence": "Persis", "privilege-escalation": "PrivEsc",
    "defense-evasion": "Evas", "credential-access": "CredAccess", "discovery": "Disc",
    "lateral-movement": "LatMov", "collection": "Collect", "command-and-control": "C2",
    "exfiltration": "Exfil", "impact": "Impact",
}

PROFILES = {
    "minimal": ["Timestamp", "Host", "Channel", "Program", "Level", "RuleTitle", "Details"],
    "standard": ["Timestamp", "Host", "Channel", "Program", "Level", "RuleTitle", "Details",
                 "MitreTactics", "MitreTags", "RuleFile", "SourceFile"],
    "verbose": ["Timestamp", "Host", "Channel", "Program", "Level", "RuleTitle", "Details",
                "MitreTactics", "MitreTags", "RuleID", "RuleFile", "SourceFile", "Line", "Message"],
}

COLORS = {"critical": "\033[1;31m", "high": "\033[33m", "medium": "\033[93m",
          "low": "\033[32m", "informational": "\033[37m"}
RESET = "\033[0m"


def is_compressed_name(f: str) -> bool:
    from .fileio import COMPRESSED_EXT, compression_of
    return f.lower().endswith(COMPRESSED_EXT) or compression_of(Path(f)) is not None


def mitre(tags: list[str]) -> tuple[str, str]:
    tactics, techs = [], []
    for t in tags:
        t = t.lower()
        if not t.startswith("attack."):
            continue
        v = t[7:]
        if v in TACTICS:
            tactics.append(TACTICS[v])
        elif v.startswith("t") and v[1:2].isdigit():
            techs.append(v.upper())
    return " ¦ ".join(tactics), " ¦ ".join(techs)


def details_str(d: dict) -> str:
    return " ¦ ".join(f"{k}: {v}" for k, v in d.items())


def row(d: Detection, profile: str, rule_root_strip: str = "") -> dict:
    tac, tech = mitre(d.tags)
    ev = d.event
    full = {
        "Timestamp": ev.timestamp.isoformat(sep=" ", timespec="seconds"),
        "Host": ev.host, "Channel": ev.channel + (f"/{ev.category}" if ev.category else ""),
        "Program": ev.program, "Level": LEVEL_ABBR[d.level], "RuleTitle": d.rule_title,
        "Details": details_str(d.details), "MitreTactics": tac, "MitreTags": tech,
        "RuleID": d.rule_id, "RuleFile": PurePath(d.rule_path).name, "SourceFile": ev.source_file,
        "Line": ev.line_no, "Message": ev.message,
    }
    return {k: full[k] for k in PROFILES[profile]}


def write_csv(dets: Iterable[Detection], fh: IO, profile: str):
    w = csv.DictWriter(fh, fieldnames=PROFILES[profile], quoting=csv.QUOTE_ALL)
    w.writeheader()
    for d in dets:
        w.writerow(row(d, profile))


def write_json(dets: Iterable[Detection], fh: IO, profile: str, jsonl: bool):
    def obj(d):
        r = row(d, profile)
        r["Details"] = d.details          # structured in JSON, like Hayabusa
        r["MitreTactics"] = [x for x in r.get("MitreTactics", "").split(" ¦ ") if x] if "MitreTactics" in r else None
        r["MitreTags"] = [x for x in r.get("MitreTags", "").split(" ¦ ") if x] if "MitreTags" in r else None
        if d.correlation:
            r["Correlation"] = True
        return {k: v for k, v in r.items() if v is not None}
    if jsonl:
        for d in dets:
            fh.write(json.dumps(obj(d), ensure_ascii=False, default=str) + "\n")
    else:
        json.dump([obj(d) for d in dets], fh, ensure_ascii=False, indent=2, default=str)


def color(level: str, text: str, enabled: bool) -> str:
    return f"{COLORS[level]}{text}{RESET}" if enabled else text


def print_summary(dets: list[Detection], stats, rs, out=sys.stderr, use_color=None, top=5):
    use_color = out.isatty() if use_color is None else use_color
    p = lambda *a: print(*a, file=out)
    p("")
    p("Results Summary:")
    p(f"  Rules loaded: {len(rs.rules)} detection, {len(rs.correlations)} correlation"
      f"  (errors: {len(rs.errors)}, skipped: {sum(rs.skipped.values())})")
    ncomp = sum(1 for f in stats.files if is_compressed_name(f))
    p(f"  Files with events: {len(stats.files)} ({ncomp} compressed)   Events scanned: {stats.events:,}")
    if stats.first:
        p(f"  First timestamp: {stats.first.isoformat(sep=' ', timespec='seconds')}")
        p(f"  Last timestamp:  {stats.last.isoformat(sep=' ', timespec='seconds')}")
    hit_events = len({id(d.event) for d in dets})
    if stats.events:
        p(f"  Events with hits / total: {hit_events:,} / {stats.events:,} "
          f"(data reduction: {100 - hit_events * 100 / stats.events:.2f}%)")
    p("")
    lc = Counter(d.level for d in dets)
    for lvl in reversed(LEVELS):
        uniq = len({d.rule_title for d in dets if d.level == lvl})
        p(color(lvl, f"  Total | Unique {lvl} detections: {lc[lvl]:,} | {uniq}", use_color))
    p("")
    hosts = Counter(d.event.host for d in dets)
    if hosts:
        p("  Hosts with most detections: " + ", ".join(f"{h} ({n})" for h, n in hosts.most_common(5)))
    for lvl in reversed(LEVELS):
        titles = Counter(d.rule_title for d in dets if d.level == lvl)
        if titles:
            p(color(lvl, f"  Top {lvl} alerts:", use_color))
            for t, n in titles.most_common(top):
                p(color(lvl, f"    {t} ({n})", use_color))
    if stats.rule_errors:
        p(f"\n  Rule runtime errors: {stats.rule_errors}")
