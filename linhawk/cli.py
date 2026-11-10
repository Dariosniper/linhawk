"""LinHawk command line interface (commands modelled after Hayabusa)."""

from __future__ import annotations

import argparse
import csv
import json
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from . import __version__
from .engine import in_range, scan, scan_files_parallel
from .output import PROFILES, print_summary, write_csv, write_json
from .parsers import iter_files, load_events
from .sigma import LEVELS, load_rules

import os

FROZEN = getattr(sys, "frozen", False)          # PyInstaller executable (linhawk.exe)
BUNDLED_RULES = Path(__file__).resolve().parent / "rules"
EXE_DIR = Path(sys.executable).resolve().parent if FROZEN else None


def _data_home() -> Path:
    if os.environ.get("LINHAWK_HOME"):
        return Path(os.environ["LINHAWK_HOME"])
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "linhawk"
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "linhawk"


SIGMA_DIR = _data_home() / "sigma"
PORTABLE_RULES = EXE_DIR / "rules" if EXE_DIR else None   # Hayabusa-style: rules/ next to the exe


def default_rules() -> list[Path]:
    """Bundled LinHawk rules + SigmaHQ rules from `update-rules` + rules/ next to the exe."""
    out = [BUNDLED_RULES]
    if SIGMA_DIR.exists():
        out.append(SIGMA_DIR)
    if PORTABLE_RULES and PORTABLE_RULES.exists():
        out.append(PORTABLE_RULES)
    return out


BANNER = r"""
  _     _       _   _                 _
 | |   (_)_ __ | | | | __ ___      _| | __
 | |   | | '_ \| |_| |/ _` \ \ /\ / / |/ /
 | |___| | | | |  _  | (_| |\ V  V /|   <
 |_____|_|_| |_|_| |_|\__,_| \_/\_/ |_|\_\  v{v}
   Linux log fast forensics & threat hunting
"""


def err(*a):
    print(*a, file=sys.stderr)


def get_tz(name: str | None):
    if not name or name.lower() == "local":
        return datetime.now().astimezone().tzinfo
    if name.upper() == "UTC":
        return timezone.utc
    try:
        return ZoneInfo(name)
    except Exception:   # ZoneInfoNotFoundError: Windows has no system tz database -> pip install tzdata
        raise SystemExit(f"Unknown timezone {name!r} (on Windows install the 'tzdata' package)")


def parse_dt(s: str | None, tz):
    if not s:
        return None
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=tz)


def detect_hostname(inputs: list[str]) -> tuple[str, str] | None:
    """Hostname of an imaged system: <input>/../../etc/hostname and similar (e.g. a
    mounted image /mnt/image/var/log -> /mnt/image/etc/hostname)."""
    for inp in inputs:
        p = Path(inp).resolve()
        for base in [p, *list(p.parents)[:4]]:
            # only a system root whose var/ contains the input (live /var/log, mounted image <root>/var/log);
            # never the analyst's own /etc for logs copied to e.g. ~/cases/x or /tmp
            if not (p == base / "var" or (base / "var") in p.parents):
                continue
            for rel, key in (("etc/hostname", None), ("etc/HOSTNAME", None), ("etc/sysconfig/network", "HOSTNAME=")):
                f = base / rel
                try:
                    if not f.is_file():
                        continue
                    for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                        line = line.strip()
                        if key:
                            if line.startswith(key):
                                line = line[len(key):].strip().strip('"')
                            else:
                                continue
                        if line and not line.startswith("#"):
                            return line.split(".")[0] if key is None else line, str(f)
                except OSError:
                    continue
    return None


def resolve_hostname(args):
    """-H wins; otherwise try to read the hostname from the image's /etc."""
    if args.hostname:
        return
    found = detect_hostname(args.input)
    if found:
        args.hostname = found[0]
        if not args.quiet:
            err(f"Hostname for events without one: {found[0]} (from {found[1]}; override with -H)")


def events_from(args, tz):
    resolve_hostname(args)
    skipped = []
    evs = load_events(args.input, tz, args.year,
                      on_skip=lambda f, why, sample="": skipped.append((str(f), why, sample)))
    if args.hostname:   # auditd logs usually carry no hostname (unless log_format node=)
        evs = _fill_host(evs, args.hostname)
    return evs, skipped


def _fill_host(evs, name):
    for ev in evs:
        if ev.host == "-":
            ev.host = name
        yield ev


def common(p: argparse.ArgumentParser, rules=True):
    p.add_argument("input", nargs="+", help="log files and/or directories (recursive)")
    p.add_argument("-t", "--timezone", default="UTC",
                   help="timezone for logs without offset and for output (UTC, local, Europe/Rome...)")
    p.add_argument("-y", "--year", type=int, help="year for RFC3164 syslog lines (default: file mtime)")
    p.add_argument("--timeline-start", help="ISO datetime, e.g. 2026-11-01T00:00:00")
    p.add_argument("--timeline-end", help="ISO datetime")
    p.add_argument("-H", "--hostname", help="hostname for events without one (e.g. auditd)")
    p.add_argument("--skipped-report", metavar="CSV", help="write the list of skipped files with the reason")
    p.add_argument("-q", "--quiet", action="store_true", help="no banner")
    if rules:
        p.add_argument("-r", "--rules", action="append",
                       help="rule file/dir (repeatable). Default: bundled rules + SigmaHQ rules from update-rules")
        p.add_argument("-m", "--min-level", default="informational", choices=LEVELS)
        p.add_argument("--include-status", action="append", default=[],
                       help="also load rules with this status (e.g. deprecated, unsupported)")
        p.add_argument("-p", "--profile", default="standard", choices=list(PROFILES))
        p.add_argument("-o", "--output", help="output file (default: stdout)")
        p.add_argument("-T", "--threads", type=int, default=0,
                       help="worker processes, one file each (default: all CPU cores; 1 = sequential)")
        p.add_argument("--no-summary", action="store_true")


def cmd_timeline(args, fmt: str):
    tz = get_tz(args.timezone)
    excl = {"deprecated", "unsupported"} - set(args.include_status)
    rule_paths = [str(r) for r in (args.rules or default_rules())]
    rs = load_rules(rule_paths, args.min_level, excl)
    if not args.quiet:
        err(BANNER.format(v=__version__))
        err(f"Loaded {len(rs.rules)} detection rules and {len(rs.correlations)} correlation rules.")
        if not args.rules and not SIGMA_DIR.exists():
            err("Tip: run `linhawk update-rules` to add the SigmaHQ Linux and web rules.")
        for f, e in rs.errors[:10]:
            err(f"  [rule error] {f}: {e}")
        if len(rs.errors) > 10:
            err(f"  ... {len(rs.errors) - 10} more rule errors")
    start, end = parse_dt(args.timeline_start, tz), parse_dt(args.timeline_end, tz)
    resolve_hostname(args)
    files = [str(f) for f in iter_files(args.input)]
    workers = min(args.threads or os.cpu_count() or 1, len(files))
    if workers > 1:
        opts = {"tz": tz, "year": args.year, "host": args.hostname, "min_level": args.min_level,
                "start": start, "end": end}
        if not args.quiet:
            err(f"Scanning {len(files)} files with {workers} worker processes...")
        dets, stats, skipped = scan_files_parallel(files, rs, rule_paths, excl, opts, workers)
    else:
        events, skipped = events_from(args, tz)
        dets, stats = scan(events, rs, args.min_level, start, end)
    for d in dets:
        d.event.timestamp = d.event.timestamp.astimezone(tz)
    fh = open(args.output, "w", newline="", encoding="utf-8") if args.output else sys.stdout
    try:
        if fmt == "csv":
            write_csv(dets, fh, args.profile)
        else:
            write_json(dets, fh, args.profile, jsonl=args.jsonl)
    finally:
        if args.output:
            fh.close()
    report_skipped(skipped, args)
    if not args.no_summary:
        print_summary(dets, stats, rs)
        if args.output:
            err(f"\n  Saved: {args.output}")
    return 0


def report_skipped(skipped: list, args):
    """Summary of files that produced no events, grouped by reason (+ optional CSV report)."""
    if getattr(args, "skipped_report", None):
        with open(args.skipped_report, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["File", "Reason", "SizeBytes", "FirstLine"])
            for f, why, sample in skipped:
                try:
                    size = os.path.getsize(f)
                except OSError:
                    size = ""
                w.writerow([f, why, size, sample])
    if not skipped or args.quiet:
        return
    groups = Counter(why for _, why, _ in skipped)
    err(f"\nSkipped {len(skipped)} file(s) that produced no events:")
    from .output import is_compressed_name
    for why, n in groups.most_common():
        files = [f for f, w, _ in skipped if w == why]
        nc = sum(1 for f in files if is_compressed_name(f))
        comp = f", {nc} compressed" if nc else ""
        err(f"  {n:5d}  {why}{comp}   (e.g. {files[0]})")
    if getattr(args, "skipped_report", None):
        err(f"  Full list: {args.skipped_report}")
    else:
        err("  Full list with first line of each file: --skipped-report skipped.csv")


def cmd_metrics(args):
    tz = get_tz(args.timezone)
    events, skipped = events_from(args, tz)
    start, end = parse_dt(args.timeline_start, tz), parse_dt(args.timeline_end, tz)
    c = Counter()
    for ev in events:
        if in_range(ev, start, end):
            c[(ev.host, ev.channel, ev.program, ev.fields.get("EventType") or ev.fields.get("type") or "-")] += 1
    total = sum(c.values()) or 1
    w = csv.writer(sys.stdout)
    w.writerow(["Host", "Channel", "Program", "EventType", "Count", "Percent"])
    for (h, ch, prog, et), n in c.most_common():
        w.writerow([h, ch, prog, et, n, f"{n * 100 / total:.2f}%"])
    report_skipped(skipped, args)
    return 0


def cmd_logon_summary(args):
    """Successful / failed logons from sshd (auth.log/secure/journal) and wtmp/btmp."""
    tz = get_tz(args.timezone)
    events, skipped = events_from(args, tz)
    start, end = parse_dt(args.timeline_start, tz), parse_dt(args.timeline_end, tz)
    ok, ko = defaultdict(int), defaultdict(int)
    first, last = {}, {}
    for ev in events:
        if not in_range(ev, start, end):
            continue
        f = ev.fields
        et = f.get("EventType", "")
        src = f.get("SrcIP") or f.get("SrcHost") or ""
        if et == "SSH_LOGIN_SUCCESS":
            key, bucket = (ev.host, f.get("User"), src, f"sshd/{f.get('AuthMethod', '')}"), ok
        elif et == "SSH_LOGIN_FAILED":
            key, bucket = (ev.host, f.get("User"), src, f"sshd/{f.get('AuthMethod', '')}"), ko
        elif et == "LOGIN":
            key, bucket = (ev.host, f.get("User"), src, f"wtmp/{_tty_kind(f.get('Tty', ''))}"), ok
        elif et == "FAILED_LOGIN":
            key, bucket = (ev.host, f.get("User"), src, f"btmp/{_tty_kind(f.get('Tty', ''))}"), ko
        else:
            continue
        bucket[key] += 1
        if key not in first or ev.timestamp < first[key]:
            first[key] = ev.timestamp
        if key not in last or ev.timestamp > last[key]:
            last[key] = ev.timestamp
    w = csv.writer(sys.stdout)
    for title, data in (("Successful logons", ok), ("Failed logons", ko)):
        w.writerow([f"# {title}"])
        w.writerow(["Count", "Host", "User", "Source", "Origin", "FirstSeen", "LastSeen"])
        for key, n in sorted(data.items(), key=lambda x: -x[1]):
            w.writerow([n, *key, first[key].astimezone(tz).isoformat(timespec="seconds"),
                        last[key].astimezone(tz).isoformat(timespec="seconds")])
        w.writerow([])
    report_skipped(skipped, args)
    return 0


def _tty_kind(tty: str) -> str:
    if tty.startswith(("pts", "ssh")):
        return "remote"
    if tty.startswith(("tty", ":", "console")):
        return "console"
    return tty or "-"


def cmd_search(args):
    tz = get_tz(args.timezone)
    events, _ = events_from(args, tz)
    start, end = parse_dt(args.timeline_start, tz), parse_dt(args.timeline_end, tz)
    rx = re.compile(args.regex, 0 if args.case_sensitive else re.I) if args.regex else None
    kws = [k if args.case_sensitive else k.lower() for k in (args.keyword or [])]
    if not rx and not kws:
        err("search: give -k/--keyword and/or -R/--regex")
        return 2
    hits = []
    for ev in events:
        if not in_range(ev, start, end):
            continue
        text = ev.message + " " + json.dumps(ev.fields, default=str, ensure_ascii=False)
        hay = text if args.case_sensitive else text.lower()
        if kws and not (all if args.and_logic else any)(k in hay for k in kws):
            continue
        if rx and not rx.search(text):
            continue
        hits.append(ev)
    hits.sort(key=lambda e: e.timestamp)
    w = csv.writer(sys.stdout)
    w.writerow(["Timestamp", "Host", "Channel", "Program", "Message", "SourceFile", "Line"])
    for ev in hits:
        w.writerow([ev.timestamp.astimezone(tz).isoformat(timespec="seconds"), ev.host,
                    ev.channel, ev.program, ev.message, ev.source_file, ev.line_no])
    return 0


SIGMA_REPO = "https://github.com/SigmaHQ/sigma"
SIGMA_PATHS = ("rules/linux", "rules-threat-hunting/linux", "rules/web/webserver_generic",
               "rules/web/product", "rules-threat-hunting/web")
RE_ET_KEEP = re.compile(r"^\s*(product:\s*linux|category:\s*webserver)\s*$", re.M)


def _install_rules(repo: Path, dest: Path) -> int:
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    for sub in SIGMA_PATHS:
        if (repo / sub).exists():
            shutil.copytree(repo / sub, dest / sub.replace("/", "_"))
    et = repo / "rules-emerging-threats"   # keep only Linux and web server emerging threats
    for f in et.rglob("*.yml") if et.exists() else []:
        if RE_ET_KEEP.search(f.read_text(encoding="utf-8", errors="ignore")):
            tgt = dest / "emerging_threats" / f.name
            tgt.parent.mkdir(exist_ok=True)
            shutil.copy(f, tgt)
    return sum(1 for _ in dest.rglob("*.yml"))


def _fetch_git(td: Path) -> Path | None:
    if not shutil.which("git"):
        return None
    repo = td / "sigma"
    cmds = [["git", "clone", "-q", "--depth", "1", "--filter=blob:none", "--sparse", SIGMA_REPO + ".git", str(repo)],
            ["git", "-C", str(repo), "sparse-checkout", "set", *SIGMA_PATHS, "rules-emerging-threats"]]
    for c in cmds:
        if subprocess.run(c).returncode:
            return None
    return repo


def _fetch_zip(td: Path) -> Path:
    """No git needed (e.g. on Windows): download the repository archive over HTTPS."""
    url = SIGMA_REPO + "/archive/refs/heads/master.zip"
    err(f"Downloading {url} ...")
    zpath = td / "sigma.zip"
    with urllib.request.urlopen(url, timeout=120) as r, open(zpath, "wb") as fh:
        shutil.copyfileobj(r, fh)
    repo = td / "sigma"
    wanted = SIGMA_PATHS + ("rules-emerging-threats",)
    with zipfile.ZipFile(zpath) as z:
        for name in z.namelist():
            rel = name.split("/", 1)[1] if "/" in name else ""
            if rel and not name.endswith("/") and rel.startswith(wanted) and rel.endswith(".yml"):
                target = repo / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(z.read(name))
    return repo


def cmd_update_rules(args):
    """Fetch SigmaHQ Linux + web server rules (git sparse checkout, or zip download)."""
    dest = Path(args.dest) if args.dest else SIGMA_DIR
    with tempfile.TemporaryDirectory() as tdn:
        td = Path(tdn)
        repo = None if args.zip else _fetch_git(td)
        if repo is None:
            try:
                repo = _fetch_zip(td)
            except OSError as e:
                err(f"update-rules failed: {e}")
                return 1
        n = _install_rules(repo, dest)
    err(f"Installed {n} SigmaHQ Linux/web rules into {dest} (Detection Rule License 1.1)")
    return 0


def _setup_console():
    """UTF-8, no CRLF doubling for CSV on Windows consoles; enable ANSI colors."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace", newline="" if stream is sys.stdout else None)
        except (AttributeError, ValueError):
            pass
    if os.name == "nt":
        os.system("")   # turns on VT100 escape processing in conhost


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="linhawk", description="Fast forensics timeline & Sigma threat hunting for Linux logs")
    ap.add_argument("-V", "--version", action="version", version=f"linhawk {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("csv-timeline", help="Sigma detections -> CSV timeline")
    common(p)
    p = sub.add_parser("json-timeline", help="Sigma detections -> JSON/JSONL timeline")
    common(p)
    p.add_argument("-L", "--jsonl", action="store_true", help="JSON Lines (for Elastic/Timesketch/jq)")
    p = sub.add_parser("metrics", help="event counts by host/channel/program/event type")
    common(p, rules=False)
    p = sub.add_parser("logon-summary", help="SSH successful/failed logons by user and source IP")
    common(p, rules=False)
    p = sub.add_parser("search", help="keyword/regex search across all events")
    common(p, rules=False)
    p.add_argument("-k", "--keyword", action="append")
    p.add_argument("-R", "--regex")
    p.add_argument("-a", "--and-logic", action="store_true", help="all keywords must match")
    p.add_argument("-c", "--case-sensitive", action="store_true")
    p = sub.add_parser("update-rules", help=f"download SigmaHQ Linux/web rules into {SIGMA_DIR}")
    p.add_argument("--dest")
    p.add_argument("--zip", action="store_true", help="download the zip archive instead of using git")

    _setup_console()
    args = ap.parse_args(argv)
    try:
        if args.cmd == "csv-timeline":
            return cmd_timeline(args, "csv")
        if args.cmd == "json-timeline":
            return cmd_timeline(args, "json")
        return {"metrics": cmd_metrics, "logon-summary": cmd_logon_summary,
                "search": cmd_search, "update-rules": cmd_update_rules}[args.cmd](args)
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
