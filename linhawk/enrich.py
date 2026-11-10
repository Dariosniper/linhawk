"""Extract structured fields from common Linux log messages (like Hayabusa's
field abbreviation / details profiles, but for sshd, sudo, su, useradd, ...)."""

from __future__ import annotations

import re

PROGRAM_SERVICES = {
    "sshd": {"auth", "sshd"},
    "sudo": {"auth", "sudo"},
    "su": {"auth"}, "login": {"auth"}, "passwd": {"auth"}, "chpasswd": {"auth"},
    "useradd": {"auth"}, "userdel": {"auth"}, "usermod": {"auth"}, "chage": {"auth"},
    "groupadd": {"auth"}, "groupdel": {"auth"}, "groupmod": {"auth"}, "gpasswd": {"auth"},
    "systemd-logind": {"auth"}, "polkitd": {"auth"}, "pkexec": {"auth"},
    "unix_chkpwd": {"auth"}, "dbus-daemon": set(),
    "cron": {"cron"}, "CRON": {"cron", "auth"}, "crond": {"cron"}, "CROND": {"cron"}, "anacron": {"cron"},
    "vsftpd": {"vsftpd"}, "clamd": {"clamav"}, "freshclam": {"clamav"},
    "guacd": {"guacamole"}, "auditd": {"auditd"},
}


def services_for_program(prog: str) -> set[str]:
    return set(PROGRAM_SERVICES.get(prog, set()))


# (program-or-None, regex, EventType). First match wins.
PATTERNS: list[tuple[str | None, re.Pattern, str]] = [
    ("sshd", re.compile(r"^Accepted (?P<AuthMethod>\S+) for (?P<User>\S+) from (?P<SrcIP>\S+) port (?P<SrcPort>\d+)"), "SSH_LOGIN_SUCCESS"),
    ("sshd", re.compile(r"^Failed (?P<AuthMethod>\S+) for (?:(?P<InvalidUser>invalid user) )?(?P<User>\S*) from (?P<SrcIP>\S+) port (?P<SrcPort>\d+)"), "SSH_LOGIN_FAILED"),
    ("sshd", re.compile(r"^Invalid user (?P<User>\S*) from (?P<SrcIP>\S+)(?: port (?P<SrcPort>\d+))?"), "SSH_INVALID_USER"),
    ("sshd", re.compile(r"^(?:Connection closed|Disconnected) by (?:(?:authenticating|invalid) user (?P<User>\S+) )?(?P<SrcIP>[\d.:a-fA-F]+) port (?P<SrcPort>\d+) \[preauth\]"), "SSH_PREAUTH_DISCONNECT"),
    ("sshd", re.compile(r"^error: maximum authentication attempts exceeded for (?:invalid user )?(?P<User>\S+) from (?P<SrcIP>\S+) port (?P<SrcPort>\d+)"), "SSH_MAX_AUTH_EXCEEDED"),
    ("sshd", re.compile(r"^Did not receive identification string from (?P<SrcIP>\S+)"), "SSH_NO_IDENT"),
    ("sshd", re.compile(r"^pam_unix\(sshd:session\): session opened for user (?P<User>[^\s(]+)"), "SSH_SESSION_OPEN"),
    ("sshd", re.compile(r"^pam_unix\(sshd:session\): session closed for user (?P<User>\S+)"), "SSH_SESSION_CLOSE"),
    ("sshd", re.compile(r"^Received disconnect from (?P<SrcIP>\S+) port (?P<SrcPort>\d+)"), "SSH_DISCONNECT"),
    ("sudo", re.compile(r"^\s*(?P<User>\S+) : (?:(?P<SudoError>[^;]*?) ; )?TTY=(?P<Tty>\S+) ; PWD=(?P<Pwd>.*?) ; USER=(?P<TargetUser>\S+) ;(?: [A-Z]+=\S+ ;)* COMMAND=(?P<Command>.*)$"), "SUDO_COMMAND"),
    ("sudo", re.compile(r"^pam_unix\(sudo:auth\): authentication failure;.*?ruser=(?P<User>\S*).*?(?:user=(?P<TargetUser>\S+))?$"), "SUDO_AUTH_FAILED"),
    ("sudo", re.compile(r"^pam_unix\(sudo:session\): session opened for user (?P<TargetUser>[^\s(]+)(?:\(uid=\d+\))? by (?P<User>[^\s(]*)"), "SUDO_SESSION_OPEN"),
    ("su", re.compile(r"^(?:\(to (?P<TargetUser>\S+)\) (?P<User>\S+) on|pam_unix\(su(?:-l)?:session\): session opened for user (?P<TargetUser2>[^\s(]+)(?:\(uid=\d+\))? by (?P<User2>[^\s(]*))"), "SU_SESSION"),
    ("su", re.compile(r"^(?:FAILED SU|pam_unix\(su(?:-l)?:auth\): authentication failure).*?(?:user=(?P<TargetUser>\S+))?$"), "SU_FAILED"),
    ("useradd", re.compile(r"^new user: name=(?P<TargetUser>[^,]+), UID=(?P<TargetUid>\d+), GID=(?P<TargetGid>\d+), home=(?P<Home>[^,]+), shell=(?P<Shell>[^,\s]+)"), "USER_CREATED"),
    ("useradd", re.compile(r"^new group: name=(?P<Group>[^,]+), GID=(?P<TargetGid>\d+)"), "GROUP_CREATED"),
    ("groupadd", re.compile(r"^new group: name=(?P<Group>[^,]+), GID=(?P<TargetGid>\d+)"), "GROUP_CREATED"),
    ("useradd", re.compile(r"^add '(?P<TargetUser>[^']+)' to (?:shadow )?group '(?P<Group>[^']+)'"), "USER_ADDED_TO_GROUP"),
    ("usermod", re.compile(r"^add '(?P<TargetUser>[^']+)' to (?:shadow )?group '(?P<Group>[^']+)'"), "USER_ADDED_TO_GROUP"),
    ("gpasswd", re.compile(r"^user (?P<TargetUser>\S+) added by (?P<User>\S+) to group (?P<Group>\S+)"), "USER_ADDED_TO_GROUP"),
    ("userdel", re.compile(r"^delete user '(?P<TargetUser>[^']+)'"), "USER_DELETED"),
    ("passwd", re.compile(r"^pam_unix\(passwd:chauthtok\): password changed for (?P<TargetUser>\S+)"), "PASSWORD_CHANGED"),
    ("chpasswd", re.compile(r"^pam_unix\(chpasswd:chauthtok\): password changed for (?P<TargetUser>\S+)"), "PASSWORD_CHANGED"),
    ("CRON", re.compile(r"^\((?P<User>[^)]+)\) CMD \((?P<Command>.*)\)$"), "CRON_EXEC"),
    ("cron", re.compile(r"^\((?P<User>[^)]+)\) CMD \((?P<Command>.*)\)$"), "CRON_EXEC"),
    ("CROND", re.compile(r"^\((?P<User>[^)]+)\) CMD \((?P<Command>.*)\)$"), "CRON_EXEC"),
    ("crond", re.compile(r"^\((?P<User>[^)]+)\) CMD \((?P<Command>.*)\)$"), "CRON_EXEC"),
    ("crontab", re.compile(r"^\((?P<User>[^)]+)\) (?P<Action>REPLACE|BEGIN EDIT|END EDIT|DELETE) \((?P<TargetUser>[^)]+)\)"), "CRONTAB_CHANGE"),
    ("systemd-logind", re.compile(r"^New session (?P<SessionId>\S+) of user (?P<User>[^.]+)\."), "LOGIN_SESSION_NEW"),
    ("systemd", re.compile(r"^Started (?P<Unit>.+?)\.?$"), "SERVICE_STARTED"),
    ("kernel", re.compile(r"(?P<Module>\S+): loading out-of-tree module taints kernel"), "KERNEL_MODULE_TAINT"),
    ("kernel", re.compile(r"\[UFW (?P<Action>\w+)\].*?SRC=(?P<SrcIP>\S+) DST=(?P<DstIP>\S+).*?PROTO=(?P<Proto>\S+)(?:.*?DPT=(?P<DstPort>\d+))?"), "FIREWALL"),
    # package managers (application logs: yum.log, dnf.rpm.log, dpkg.log)
    ("yum", re.compile(r"^(?:\w+ )?(?P<Action>Installed|Updated|Upgraded|Erased|Removed|Obsoleted|Reinstalled|Downgraded): (?P<Package>\S+)"), "PACKAGE_CHANGE"),
    ("dnf.rpm", re.compile(r"^(?:\w+ )?(?P<Action>Installed|Upgraded|Erased|Removed|Obsoleted|Reinstalled|Downgraded|Upgrade|Install|Erase): (?P<Package>\S+)"), "PACKAGE_CHANGE"),
    ("dpkg", re.compile(r"^(?P<Action>install|upgrade|remove|purge) (?P<Package>\S+)"), "PACKAGE_CHANGE"),
    (None, re.compile(r"pam_unix\((?P<PamService>[^:]+):auth\): authentication failure;.*?(?:user=(?P<TargetUser>\S+))?$"), "PAM_AUTH_FAILED"),
]

RENAMES = {"TargetUser2": "TargetUser", "User2": "User"}


def enrich_message(prog: str, msg: str) -> dict:
    if not isinstance(msg, str) or not msg:
        return {}
    for p_prog, rx, etype in PATTERNS:
        if p_prog is not None and p_prog != prog:
            continue
        m = rx.search(msg)
        if m:
            out = {"EventType": etype}
            for k, v in m.groupdict().items():
                if v is not None:
                    out[RENAMES.get(k, k)] = v.strip()
            if "InvalidUser" in out:
                out["InvalidUser"] = True
            return out
    return {}
