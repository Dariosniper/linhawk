"""Web server log parsers: Apache / nginx access logs (common, combined, vhost_combined,
JSON) and error logs.

Access events use the W3C-style field names expected by SigmaHQ `category: webserver`
rules, plus friendly aliases:

  c-ip / SrcIP, cs-username / User, cs-method / Method, cs-uri-stem (path),
  cs-uri-query (FULL request URI, path + query: SigmaHQ generic rules look for
  traversal / injection strings there), cs-uri, cs-version, sc-status / Status,
  sc-bytes, cs-referer, cs-user-agent / UserAgent, cs-host / VHost, UriDecoded
"""

from __future__ import annotations

import json
import re
from datetime import datetime, tzinfo
from pathlib import Path
from typing import Iterator
from urllib.parse import unquote_plus

from .events import Event

RE_ACCESS = re.compile(
    r'^(?:(?P<vhost>[^\s"\[]+?)(?::(?P<vport>\d+))?\s+)?'
    r'(?P<ip>[0-9A-Fa-f.:]+|-)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+'
    r'\[(?P<ts>\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}(?:\.\d+)? [+-]\d{4})\]\s+'
    r'"(?P<req>(?:[^"\\]|\\.)*)"\s+(?P<status>\d{3}|-)\s+(?P<bytes>\d+|-)'
    r'(?:\s+"(?P<ref>(?:[^"\\]|\\.)*)"\s+"(?P<ua>(?:[^"\\]|\\.)*)")?(?P<rest>.*)$')
RE_REQ = re.compile(r"^(?P<method>[A-Z][A-Z_-]*)\s+(?P<uri>\S+)(?:\s+(?P<ver>HTTP/[\d.]+))?$")

RE_APACHE_ERR = re.compile(
    r"^\[(?P<ts>\w{3} \w{3} +\d{1,2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4})\] \[(?:(?P<module>[^:\]]*):)?(?P<level>[^\]]+)\]"
    r"(?: \[pid (?P<pid>\d+)(?::tid \d+)?\])?(?: \[client (?P<client>[^\]]+)\])? (?P<msg>.*)$")
RE_NGINX_ERR = re.compile(
    r"^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] (?P<pid>\d+)#(?P<tid>\d+): (?:\*(?P<cid>\d+) )?(?P<msg>.*)$")
RE_NGINX_KV = re.compile(r', (client|server|request|upstream|host|referrer): "?([^",]*)"?')

WEB_FILE_HINTS = (("nginx", {"nginx"}), ("apache", {"apache"}), ("httpd", {"apache"}))


def products_for(path: Path) -> set[str]:
    p = str(path).lower()
    for hint, prods in WEB_FILE_HINTS:
        if hint in p:
            return set(prods)
    return {"apache", "nginx"}       # combined format is shared, product unknown


def _unescape(s: str | None) -> str:
    if not s or s == "-":
        return ""
    return s.replace('\\"', '"').replace("\\\\", "\\")


def _decode(uri: str) -> str:
    """Double URL-decoding, to expose %252e%252e style evasions."""
    try:
        once = unquote_plus(uri)
        return unquote_plus(once) if "%" in once else once
    except Exception:
        return uri


def access_fields(ip, user, method, uri, ver, status, size, ref, ua, vhost, raw_req) -> dict:
    stem, _, query = uri.partition("?")
    f = {
        "EventType": "WEB_REQUEST",
        "c-ip": ip, "SrcIP": ip,
        "cs-username": user, "User": user,
        "cs-method": method, "Method": method,
        "cs-uri-stem": stem, "cs-uri-query": uri, "cs-uri": uri, "Query": query,
        "UriDecoded": _decode(uri),
        "cs-version": ver,
        "sc-status": status, "Status": status,
        "sc-bytes": size,
        "cs-referer": ref, "Referer": ref,
        "cs-user-agent": ua, "UserAgent": ua,
        "cs-host": vhost, "VHost": vhost,
        "Request": raw_req,
    }
    ext = stem.rsplit("/", 1)[-1]
    f["c-uri-extension"] = ext.rsplit(".", 1)[-1].lower() if "." in ext else ""
    return {k: v for k, v in f.items() if v not in (None, "")}


def _status(s):
    try:
        return int(s)
    except (TypeError, ValueError):
        return None


class WebAccessParser:
    def __init__(self, tz: tzinfo):
        self.tz = tz

    def parse(self, lines: Iterator[str], path: Path) -> Iterator[Event]:
        prods = products_for(path)
        for n, line in enumerate(lines, 1):
            m = RE_ACCESS.match(line)
            if not m:
                continue
            try:
                ts = datetime.strptime(re.sub(r"\.\d+", "", m["ts"]), "%d/%b/%Y:%H:%M:%S %z")
            except ValueError:
                continue
            raw_req = _unescape(m["req"])
            rm = RE_REQ.match(raw_req)
            method, uri, ver = (rm["method"], rm["uri"], rm["ver"] or "") if rm else ("", raw_req, "")
            size = 0 if m["bytes"] == "-" else int(m["bytes"])
            user = "" if m["user"] == "-" else m["user"]
            fields = access_fields(m["ip"], user, method, uri, ver, _status(m["status"]), size,
                                   _unescape(m["ref"]), _unescape(m["ua"]), m["vhost"] or "", raw_req)
            if rm is None and raw_req:
                fields["MalformedRequest"] = True
            yield Event(ts, "-", "webaccess", "httpd", line, str(path), {"access"},
                        "webserver", fields, n, set(prods))

    def parse_json(self, lines: Iterator[str], path: Path) -> Iterator[Event]:
        """nginx `log_format ... escape=json` / Apache JSON / Caddy-like structured logs."""
        prods = products_for(path)
        for n, line in enumerate(lines, 1):
            try:
                j = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(j, dict):
                continue
            g = lambda *ks: next((j[k] for k in ks if k in j and j[k] not in (None, "-")), "")
            ts = parse_any_ts(str(g("time_iso8601", "@timestamp", "timestamp", "time", "time_local")), self.tz)
            if ts is None:
                continue
            raw_req = str(g("request"))
            rm = RE_REQ.match(raw_req) if raw_req else None
            method = str(g("request_method", "method")) or (rm["method"] if rm else "")
            uri = str(g("request_uri", "uri", "url")) or (rm["uri"] if rm else raw_req)
            ver = str(g("server_protocol", "protocol")) or (rm["ver"] or "" if rm else "")
            fields = access_fields(str(g("remote_addr", "client_ip", "clientip", "remote_ip")), str(g("remote_user")),
                                   method, uri, ver, _status(g("status", "response")), _status(g("body_bytes_sent", "bytes")),
                                   str(g("http_referer", "referer", "referrer")), str(g("http_user_agent", "user_agent", "agent")),
                                   str(g("host", "server_name", "vhost")), raw_req or f"{method} {uri} {ver}".strip())
            yield Event(ts, "-", "webaccess", "httpd", line, str(path), {"access"},
                        "webserver", fields, n, set(prods))


def parse_any_ts(s: str, tz: tzinfo) -> datetime | None:
    if not s:
        return None
    for fmt in ("%d/%b/%Y:%H:%M:%S %z",):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            pass
    try:
        if re.fullmatch(r"\d+(\.\d+)?", s):
            return datetime.fromtimestamp(float(s), tz=tz)
        ts = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return ts if ts.tzinfo else ts.replace(tzinfo=tz)
    except ValueError:
        return None


def _err_services(product: str, msg: str) -> set[str]:
    sv = {product, "weberror"}           # "weberror": LinHawk service covering both servers
    if "ModSecurity" in msg:
        sv.add("modsecurity")
    return sv


class WebErrorParser:
    """Apache 2.2/2.4 and nginx error logs -> Sigma `service: apache` / `service: nginx`."""

    def __init__(self, tz: tzinfo):
        self.tz = tz

    def parse(self, lines: Iterator[str], path: Path) -> Iterator[Event]:
        for n, line in enumerate(lines, 1):
            m = RE_APACHE_ERR.match(line)
            if m:
                try:
                    ts = datetime.strptime(re.sub(r"\.\d+", "", re.sub(r" +", " ", m["ts"])), "%a %b %d %H:%M:%S %Y").replace(tzinfo=self.tz)
                except ValueError:
                    continue
                client = m["client"] or ""
                fields = {"EventType": "WEB_ERROR", "Level": m["level"], "Module": m["module"] or "",
                          "SrcIP": client.rsplit(":", 1)[0] if client.count(":") == 1 or "]" in client else client,
                          "Pid": m["pid"] or ""}
                code = re.match(r"(AH\d{5}):", m["msg"])
                if code:
                    fields["ErrorCode"] = code.group(1)
                yield Event(ts, "-", "weberror", "apache", m["msg"], str(path), _err_services("apache", m["msg"]), None,
                            {k: v for k, v in fields.items() if v}, n, {"apache"})
                continue
            m = RE_NGINX_ERR.match(line)
            if m:
                try:
                    ts = datetime.strptime(m["ts"], "%Y/%m/%d %H:%M:%S").replace(tzinfo=self.tz)
                except ValueError:
                    continue
                kv = dict(RE_NGINX_KV.findall(m["msg"]))
                fields = {"EventType": "WEB_ERROR", "Level": m["level"], "Pid": m["pid"],
                          "SrcIP": kv.get("client", ""), "VHost": kv.get("host", ""),
                          "Request": kv.get("request", ""), "Upstream": kv.get("upstream", "")}
                yield Event(ts, "-", "weberror", "nginx", m["msg"], str(path), _err_services("nginx", m["msg"]), None,
                            {k: v for k, v in fields.items() if v}, n, {"nginx"})


def looks_like_access(line: str) -> bool:
    return RE_ACCESS.match(line) is not None


def looks_like_error(line: str) -> bool:
    return RE_APACHE_ERR.match(line) is not None or RE_NGINX_ERR.match(line) is not None


def looks_like_access_json(obj: dict) -> bool:
    keys = set(obj)
    return bool(keys & {"remote_addr", "request_uri", "http_user_agent", "client_ip"}) and \
        bool(keys & {"status", "request", "request_uri", "response"})
