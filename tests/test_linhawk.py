from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from linhawk.engine import scan
from linhawk.events import Event
from linhawk.parsers import SyslogParser, load_events, parse_audit_line
from linhawk.sigma import RuleError, build_rule, load_rules

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "tests" / "samples"
UTC = timezone.utc


def ev(msg="", fields=None, services=("syslog",), category=None):
    return Event(datetime(2026, 1, 1, tzinfo=UTC), "h", "syslog", "p", msg, "f",
                 set(services), category, fields or {})


def rule(detection, logsource=None):
    return build_rule({"title": "t", "logsource": logsource or {"product": "linux", "service": "syslog"},
                       "detection": yaml.safe_load(detection)}, "x.yml")


# ------------------------------------------------------------------ parsers

def test_syslog_rfc3164_and_iso(tmp_path):
    f = tmp_path / "auth.log"
    f.write_text("Nov  5 10:00:01 web01 sshd[12]: Accepted password for bob from 1.2.3.4 port 22 ssh2\n"
                 "2026-11-05T10:00:02.123456789+01:00 web01 sudo: bob : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls\n")
    evs = list(SyslogParser(UTC, 2026).parse(f))
    assert evs[0].fields["EventType"] == "SSH_LOGIN_SUCCESS"
    assert evs[0].fields["SrcIP"] == "1.2.3.4" and {"auth", "sshd"} <= evs[0].services
    assert evs[1].timestamp.utcoffset().total_seconds() == 3600
    assert evs[1].fields["Command"] == "/bin/ls" and "sudo" in evs[1].services


def test_syslog_year_rollover(tmp_path):
    import os
    f = tmp_path / "syslog"
    f.write_text("Dec 31 23:59:59 h cron[1]: x\nJan  1 00:00:01 h cron[1]: y\n")
    ts = datetime(2027, 1, 1, 12, tzinfo=UTC).timestamp()
    os.utime(f, (ts, ts))
    evs = list(SyslogParser(UTC).parse(f))
    assert evs[0].timestamp.year == 2026 and evs[1].timestamp.year == 2027


def test_audit_hex_and_enriched():
    r = parse_audit_line('type=EXECVE msg=audit(1700000000.100:5): argc=2 a0="bash" a1=2D6320696420')
    assert r["a1"] == "-c id"
    r = parse_audit_line('type=USER_AUTH msg=audit(1.0:6): pid=1 msg=\'op=PAM:auth acct="root" res=failed\'\x1dUID="root"')
    assert r["acct"] == "root" and r["res"] == "failed" and r["UID"] == "root"


def test_auditd_process_creation_and_parent():
    evs = list(load_events([str(SAMPLES / "audit.log")], UTC))
    procs = [e for e in evs if e.category == "process_creation"]
    rev = next(e for e in procs if "/dev/tcp/" in e.fields["CommandLine"])
    assert rev.fields["Image"] == "/bin/bash" and rev.fields["ParentImage"] == "/bin/bash"
    assert any(e.category == "file_event" and e.fields["TargetFilename"] == "/etc/ld.so.preload" for e in evs)


def test_journald_json():
    evs = list(load_events([str(SAMPLES / "journal.json")], UTC))
    assert evs[0].host == "web01" and evs[0].fields["EventType"] == "KERNEL_MODULE_TAINT"


# ------------------------------------------------------------------ sigma

@pytest.mark.parametrize("det,fields,msg,expected", [
    ("{sel: {User: ROOT}, condition: sel}", {"User": "root"}, "", True),          # case-insensitive equals
    ("{sel: {User|cased: ROOT}, condition: sel}", {"User": "root"}, "", False),
    ("{sel: {Cmd|contains: 'dev/tcp'}, condition: sel}", {"Cmd": "bash >& /dev/tcp/1"}, "", True),
    ("{sel: {Cmd|startswith: '/tmp/'}, condition: sel}", {"Cmd": "/tmp/x"}, "", True),
    ("{sel: {Cmd|endswith: '.sh'}, condition: sel}", {"Cmd": "/tmp/x.sh"}, "", True),
    ("{sel: {Cmd: '/tmp/*.sh'}, condition: sel}", {"Cmd": "/tmp/a/b.sh"}, "", True),
    ("{sel: {Cmd: 'a\\*b'}, condition: sel}", {"Cmd": "a*b"}, "", True),             # escaped wildcard
    ("{sel: {Cmd: 'a\\*b'}, condition: sel}", {"Cmd": "axxb"}, "", False),
    ("{sel: {Cmd|contains|all: [curl, '| sh']}, condition: sel}", {"Cmd": "curl x | sh"}, "", True),
    ("{sel: {Cmd|contains|all: [curl, '| sh']}, condition: sel}", {"Cmd": "curl x"}, "", False),
    ("{sel: {Cmd|re: '^nc\\s+-e'}, condition: sel}", {"Cmd": "nc -e /bin/sh"}, "", True),
    ("{sel: {IP|cidr: 10.0.0.0/8}, condition: sel}", {"IP": "10.1.2.3"}, "", True),
    ("{sel: {Uid|lt: 1000}, condition: sel}", {"Uid": "0"}, "", True),
    ("{sel: {Missing: null}, condition: sel}", {}, "", True),
    ("{sel: {X|exists: true}, condition: sel}", {"X": "1"}, "", True),
    ("{sel: {Cmd|base64offset|contains: 'whoami'}, condition: sel}", {"Cmd": "echo d2hvYW1p | base64 -d"}, "", True),
    ("{kw: [Fork*bomb, 'segfault'], condition: kw}", {}, "kernel: fork xx BOMB", True),
    ("{kw: [Fork*bomb, 'segfault'], condition: kw}", {}, "nothing", False),
    ("{a: {X: 1}, b: {Y: 2}, condition: 'a and not b'}", {"X": 1, "Y": 3}, "", True),
    ("{s1: {X: 1}, s2: {Y: 2}, condition: '1 of s*'}", {"Y": 2}, "", True),
    ("{s1: {X: 1}, s2: {Y: 2}, condition: 'all of them'}", {"Y": 2}, "", False),
    ("{a: {X: 1}, b: {Y: 2}, c: {Z: 3}, condition: 'a or (b and c)'}", {"Y": 2, "Z": 3}, "", True),
    ("{sel: [{X: 1}, {Y: 2}], condition: sel}", {"Y": 2}, "", True),
])
def test_sigma_matching(det, fields, msg, expected):
    assert rule(det).match(ev(msg, fields)) is expected


def test_bad_condition():
    with pytest.raises(RuleError):
        rule("{sel: {X: 1}, condition: 'sel and nope'}")


def test_logsource_routing():
    r = rule("{sel: {X: 1}, condition: sel}", {"product": "linux", "category": "process_creation"})
    assert not r.match(ev(fields={"X": 1}))
    assert r.match(ev(fields={"X": 1}, category="process_creation"))


# ------------------------------------------------------------------ end to end

def test_end_to_end_bundled_rules():
    rs = load_rules([str(ROOT / "linhawk" / "rules")])
    assert not rs.errors
    dets, stats = scan(load_events([str(SAMPLES)], UTC, 2026), rs, "low")
    titles = {d.rule_title for d in dets}
    for t in ["SSH Brute Force From Single Source", "SSH Password Spraying (Many Users From One Source)",
              "SSH Successful Login After Failures From Same Source", "Reverse Shell Command Line",
              "User Created With UID 0", "User Added To Privileged Group", "ld.so.preload Created",
              "Out-Of-Tree Kernel Module Tainted Kernel", "Suspicious Command Executed By Cron"]:
        assert t in titles, t
    # base rule of a correlation (generate: false) must not appear on its own
    assert "SSH Failed Login" not in titles
    assert stats.events > 100
    bf = next(d for d in dets if d.rule_title == "SSH Brute Force From Single Source")
    assert bf.details["SrcIP"] == "203.0.113.50" and bf.details["Count"] >= 10


from linhawk.cli import SIGMA_DIR


@pytest.mark.skipif(not SIGMA_DIR.exists(), reason="run `linhawk update-rules` first")
def test_sigmahq_rules_load_cleanly():
    rs = load_rules([str(SIGMA_DIR)])
    assert len(rs.rules) > 200
    assert not rs.errors, rs.errors[:5]


# ------------------------------------------------------------------ web server logs

def test_web_access_combined_and_vhost(tmp_path):
    from linhawk.webparsers import RE_ACCESS
    f = tmp_path / "access.log"
    f.write_text('203.0.113.9 - bob [05/Nov/2026:10:00:00 +0100] "GET /a.php?x=..%2F..%2Fetc%2Fpasswd HTTP/1.1" 200 12 "-" "curl/8"\n'
                 'www.example.org:443 203.0.113.9 - - [05/Nov/2026:10:00:01 +0100] "POST /login HTTP/2.0" 302 0 "https://r/" "UA \\"q\\""\n'
                 '203.0.113.9 - - [05/Nov/2026:10:00:02 +0100] "\\x16\\x03\\x01" 400 157 "-" "-"\n')
    evs = list(load_events([str(f)], UTC))
    assert len(evs) == 3 and all(e.category == "webserver" for e in evs)
    a, b, c = (e.fields for e in evs)
    assert a["c-ip"] == "203.0.113.9" and a["User"] == "bob" and a["sc-status"] == 200
    assert a["cs-uri-stem"] == "/a.php" and a["UriDecoded"].endswith("../../etc/passwd")
    assert evs[0].timestamp.utcoffset().total_seconds() == 3600
    assert b["cs-host"] == "www.example.org" and b["cs-method"] == "POST" and b["UserAgent"] == 'UA "q"'
    assert c.get("MalformedRequest") is True


def test_web_error_logs():
    evs = list(load_events([str(SAMPLES / "web" / "apache_error.log"), str(SAMPLES / "web" / "nginx_error.log")], UTC))
    ap = [e for e in evs if e.program == "apache"]
    ng = [e for e in evs if e.program == "nginx"]
    assert ap[0].fields["SrcIP"] == "203.0.113.82" and "modsecurity" in ap[2].services
    assert ng[0].fields["SrcIP"] == "203.0.113.82" and ng[0].fields["Request"] == "GET /x.php HTTP/1.1"
    assert {"nginx", "weberror"} <= ng[0].services and ng[0].products == {"nginx"}


def test_web_product_routing():
    r = build_rule({"title": "t", "logsource": {"product": "apache"},
                    "detection": {"kw": ["x"], "condition": "kw"}}, "x.yml")
    e = ev("x", services=("apache",))
    e.products = {"nginx"}
    assert not r.match(e)
    e.products = {"apache"}
    assert r.match(e)


def test_end_to_end_web_rules():
    rs = load_rules([str(ROOT / "linhawk" / "rules")])
    dets, _ = scan(load_events([str(SAMPLES / "web")], UTC), rs, "low")
    titles = [d.rule_title for d in dets]
    for t in ["SQL Injection Attempt In Web Request", "Path Traversal With Successful Response",
              "Log4Shell JNDI Injection Attempt", "Known Web Shell Accessed", "Web Login Brute Force",
              "Web Content Discovery / Directory Brute Force", "Sensitive File Disclosed By Web Server",
              "PHP Dangerous Function Error", "ModSecurity Blocked Request"]:
        assert t in titles, t
    # scanner requests are aggregated: one alert per client + tool, not one per request
    assert titles.count("Web Vulnerability Scanner Activity") == 3
    assert "Web Vulnerability Scanner Request" not in titles


def test_update_rules_zip_extraction(tmp_path, monkeypatch):
    import io
    import zipfile
    from linhawk import cli
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("sigma-master/rules/linux/builtin/a.yml", "title: a")
        z.writestr("sigma-master/rules/windows/b.yml", "title: b")
        z.writestr("sigma-master/rules/web/webserver_generic/c.yml", "title: c")
        z.writestr("sigma-master/rules-emerging-threats/2025/d.yml", "logsource:\n    product: linux\n")
        z.writestr("sigma-master/rules-emerging-threats/2025/e.yml", "logsource:\n    product: windows\n")

    class Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    monkeypatch.setattr(cli.urllib.request, "urlopen", lambda url, timeout=0: Resp(buf.getvalue()))
    dest = tmp_path / "sigma"
    assert cli.main(["update-rules", "--zip", "--dest", str(dest)]) == 0
    names = sorted(p.name for p in dest.rglob("*.yml"))
    assert names == ["a.yml", "c.yml", "d.yml"]


def test_parallel_equals_sequential():
    from linhawk.engine import scan_files_parallel
    from linhawk.parsers import iter_files
    paths = [str(ROOT / "linhawk" / "rules")]
    rs = load_rules(paths)
    seq, _ = scan(load_events([str(SAMPLES)], UTC, 2026), rs, "low")
    opts = {"tz": UTC, "year": 2026, "host": None, "min_level": "low", "start": None, "end": None}
    files = [str(f) for f in iter_files([str(SAMPLES)])]
    par, stats, _ = scan_files_parallel(files, rs, paths, {"deprecated", "unsupported"}, opts, 2)
    key = lambda d: (d.event.timestamp, d.rule_title, d.event.source_file, d.event.line_no)
    assert sorted(map(key, seq)) == sorted(map(key, par))
    assert stats.events > 300


# ------------------------------------------------------------------ real-world /var/log (rotation, binaries)

VARLOG = SAMPLES / "varlog"


def _load(name):
    return list(load_events([str(VARLOG / name)], UTC))


@pytest.mark.parametrize("name,base,prog,rdate", [
    ("dracut.log-20151013", "dracut.log", "dracut", "2015-10-13"),
    ("messages-20151013", "messages", "messages", "2015-10-13"),
    ("secure-20151013.xz", "secure", "secure", "2015-10-13"),
    ("audit.log.3", "audit.log", "audit", None),
    ("access_log-20151013.gz", "access_log", "access", "2015-10-13"),
    ("cron.1.gz", "cron", "cron", None),
])
def test_rotation_names(name, base, prog, rdate):
    from linhawk.fileio import program_from_name, rotation_basename, rotation_date
    p = Path(name)
    assert rotation_basename(p) == base and program_from_name(p) == prog
    assert (str(rotation_date(p)) if rotation_date(p) else None) == rdate


def test_compression_by_magic_not_extension():
    assert _load("maillog-20151013")[0].program == "postfix/pickup"     # gzip, no .gz
    assert _load("secure-20151013.xz")[0].fields["EventType"] == "SSH_LOGIN_SUCCESS"
    assert _load("cron-20151013.bz2")[0].fields["Command"].startswith("curl")


def test_rotation_date_gives_syslog_year():
    evs = _load("messages-20151013")
    assert [e.timestamp.year for e in evs] == [2015, 2015]


def test_generic_ctime_with_tz_abbrev_and_continuations():
    evs = _load("dracut.log-20151013")
    assert len(evs) == 2 and evs[0].program == "dracut" and evs[0].channel == "applog"
    assert evs[0].timestamp.utcoffset().total_seconds() == 7200       # CEST
    assert "Including module: nss-softokn" in evs[0].message           # continuation lines kept


def test_generic_bsd_without_host_uses_rotation_year():
    evs = _load("yum.log-20151013")
    assert evs[0].timestamp.year == 2015 and evs[0].fields["Package"] == "2:nmap-ncat-6.40-7.el7.x86_64"


def test_python_style_app_log_is_not_syslog():
    evs = list(load_events([str(VARLOG / "tuned")], UTC))
    assert all(e.channel == "applog" and e.program == "tuned" for e in evs)
    assert evs[1].fields["Level"] == "ERROR" and "Traceback" in evs[1].message


def test_mysql_and_isodash_styles():
    my = _load("mariadb.log")
    assert my[1].timestamp.hour == 9 and my[1].timestamp.year == 2015
    assert _load("cloud-init.log")[0].timestamp.minute == 0


def test_wtmp_btmp_lastlog():
    wt = _load("wtmp")
    assert [e.fields["EventType"] for e in wt] == ["BOOT", "LOGIN", "LOGOUT"]
    assert wt[1].fields["SrcIP"] == "198.51.100.23" and wt[1].fields["Tty"] == "pts/0"
    bt = _load("btmp-20151101")
    assert len(bt) == 12 and all(e.fields["EventType"] == "FAILED_LOGIN" for e in bt)
    ll = _load("lastlog")
    assert ll[0].fields["Uid"] == 1 and ll[0].fields["SrcHost"] == "198.51.100.23"


def test_skip_reasons():
    skipped = {}
    list(load_events([str(VARLOG)], UTC, on_skip=lambda f, why, s="": skipped.__setitem__(Path(f).name, why)))
    assert skipped["spooler-20151013"] == "empty"
    assert skipped["boot.log-20151013"].startswith("empty")
    assert "dmesg" in skipped["dmesg.old"]
    assert "without a date" in skipped["anaconda.log"]
    assert "sysstat" in skipped["sa13"]
    assert "systemd journal" in skipped["system.journal"]
    assert "boot.log" in skipped and "dracut.log-20151013" not in skipped


def test_hostname_from_image(tmp_path):
    from linhawk.cli import detect_hostname
    (tmp_path / "image" / "etc").mkdir(parents=True)
    (tmp_path / "image" / "var" / "log").mkdir(parents=True)
    (tmp_path / "image" / "etc" / "hostname").write_text("web01.example.org\n")
    assert detect_hostname([str(tmp_path / "image" / "var" / "log")])[0] == "web01"


def test_varlog_detections():
    rs = load_rules([str(ROOT / "linhawk" / "rules")])
    dets, _ = scan(load_events([str(VARLOG)], UTC), rs, "low")
    titles = {d.rule_title for d in dets}
    assert {"Offensive Or Dual-Use Tool Package Installed", "Brute Force Recorded In btmp",
            "Remote Root Login Recorded In wtmp", "Suspicious Command Executed By Cron"} <= titles


def test_journald_null_list_and_bytes_values(tmp_path):
    import json as _j
    base = {"__REALTIME_TIMESTAMP": "1444723921000000", "_HOSTNAME": "h", "_PID": "1"}
    recs = [dict(base, SYSLOG_IDENTIFIER="kernel", MESSAGE=None),                       # too long -> null
            dict(base, SYSLOG_IDENTIFIER=["sshd", "sshd"], MESSAGE=list(b"Accepted password for bob from 1.2.3.4 port 22 ssh2")),
            dict(base, SYSLOG_IDENTIFIER="app", MESSAGE=["first", "second"]),
            dict(base, MESSAGE="no identifier", _COMM=None)]
    f = tmp_path / "j.json"
    f.write_text("\n".join(_j.dumps(r) for r in recs) + "\n")
    evs = list(load_events([str(f)], UTC))
    assert len(evs) == 4
    assert evs[0].message == ""
    assert evs[1].program == "sshd" and evs[1].fields["EventType"] == "SSH_LOGIN_SUCCESS"
    assert evs[2].message == "first\nsecond" and evs[3].program == "-"


def test_parser_crash_is_reported_not_fatal(tmp_path, monkeypatch):
    from linhawk import parsers
    good = tmp_path / "a.log"
    good.write_text("Oct 13 08:00:00 h sshd[1]: Accepted password for bob from 1.2.3.4 port 22 ssh2\n")
    bad = tmp_path / "b.log"
    bad.write_text("Oct 13 08:00:00 h sshd[1]: boom\n")
    orig = parsers.SyslogParser.parse

    def flaky(self, path):
        if path.name == "b.log":
            raise TypeError("simulated")
        return orig(self, path)
    monkeypatch.setattr(parsers.SyslogParser, "parse", flaky)
    skipped = []
    evs = list(load_events([str(tmp_path)], UTC, 2015, on_skip=lambda f, w, s="": skipped.append(w)))
    assert len(evs) == 1 and "parser error" in skipped[0] and "TypeError" in skipped[0]


def test_ubuntu_rotated_gz_app_logs(tmp_path):
    import gzip as gz
    (tmp_path / "apt").mkdir()
    gz.open(tmp_path / "apt" / "history.log.2.gz", "wt").write(
        "\nStart-Date: 2026-10-20  11:02:13\nCommandline: apt install nmap socat\nRequested-By: alice (1000)\n"
        "Install: nmap:amd64 (7.94+git20230807-3), socat:amd64 (1.8.0.0-4)\nEnd-Date: 2026-10-20  11:02:20\n")
    gz.open(tmp_path / "alternatives.log.1.gz", "wt").write(
        "update-alternatives 2026-10-20 11:02:19: run with --install /usr/bin/nc nc /bin/nc.openbsd 50\n")
    gz.open(tmp_path / "dpkg.log.2.gz", "wt").write("2026-10-20 11:02:15 install nmap:amd64 <none> 7.94\n")
    (tmp_path / "cups").mkdir()
    gz.open(tmp_path / "cups" / "error_log.1.gz", "wt").write("E [20/Oct/2026:11:00:00 +0200] [cups-deviced] stopped\n")
    skipped = []
    evs = list(load_events([str(tmp_path)], UTC, on_skip=lambda f, w, s="": skipped.append((f, w))))
    assert not skipped, skipped
    by = {e.program: e for e in evs}
    assert set(by) == {"apt/history", "alternatives", "dpkg", "cups/error"} and len(evs) == 4
    apt = by["apt/history"]
    assert apt.fields["Command"] == "apt install nmap socat" and apt.fields["User"] == "alice"
    assert "End-Date" in apt.message and apt.timestamp.hour == 11
    assert by["dpkg"].channel == "applog" and by["dpkg"].fields["Package"] == "nmap:amd64"
    assert by["cups/error"].timestamp.utcoffset().total_seconds() == 7200
    rs = load_rules([str(ROOT / "linhawk" / "rules")])
    dets, _ = scan(iter(evs), rs, "low")
    assert sum(d.rule_title == "Offensive Or Dual-Use Tool Package Installed" for d in dets) == 2


def test_hostname_not_taken_from_analysis_machine(tmp_path):
    from linhawk.cli import detect_hostname
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "hostname").write_text("analyst-pc\n")
    (tmp_path / "cases" / "srv01").mkdir(parents=True)
    assert detect_hostname([str(tmp_path / "cases" / "srv01")]) is None
