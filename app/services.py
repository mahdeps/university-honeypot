# -*- coding: utf-8 -*-
"""
Deceptive TCP service layer — medium-interaction bait for SSH and FTP.

The web decoy catches HTTP attackers. This adds the two protocols that brute-
force tooling (Hydra, Medusa, Metasploit's *_login modules) hammers most: SSH
and FTP. Both are SIMULATED. They speak enough of the real protocol that the
tools believe them, record every username, password and typed command into the
same event stream the dashboard and Telegram already watch — and never execute
one byte of what the attacker sends.

This is the Cowrie / Dionaea model, and it is deliberate. A real exploitable
service would let an attacker pivot off the trap onto the host; the whole
project is built on the opposite promise. A simulation captures MORE (the full
credential list, the full command transcript) while the host stays untouchable.

  SSH  — a real paramiko transport (so the handshake is genuine and Hydra's ssh
         module works), a password-auth callback that logs every try, and a fake
         shell that answers ls/whoami/uname with canned output and records the
         session. Planted weak credentials succeed so the "post-compromise"
         behaviour can be observed.
  FTP  — a plain-text listener: 220 banner, USER/PASS, 230/530. Enough for
         hydra ftp and ftp_login. The banner advertises a version Metasploit
         flags as vulnerable, and the vsftpd-2.3.4 ":)" backdoor trigger is
         detected and logged as an exploit attempt (never actioned).

Every service runs on its own daemon thread and is started AFTER any fork, the
same discipline as the Suricata tailer and the notifier.

Config (env, then app/config.py):
  HONEYPOT_SSH_ENABLE / HONEYPOT_FTP_ENABLE   1 to run each        (default: 1)
  HONEYPOT_SSH_PORT / HONEYPOT_FTP_PORT       listen ports         (2222 / 2121)
  HONEYPOT_SERVICE_BIND                       bind address         (0.0.0.0)
  HONEYPOT_WEAK_CREDS   user:pass,user:pass — the planted logins that succeed
  HONEYPOT_SSH_BANNER   SSH ident string      (default: OpenSSH_8.9p1 Ubuntu)
  HONEYPOT_FTP_BANNER   FTP 220 banner        (default: vsFTPd 2.3.4 — bait)
"""

import os
import socket
import threading
import time

from . import config, logger

BIND = config.get("HONEYPOT_SERVICE_BIND", "0.0.0.0")

# Planted weak credentials that "work". These are exactly the pairs a default
# Hydra / rockyou run tries first, so the success path fires quickly in a demo.
_DEFAULT_WEAK = ("root:root,root:toor,root:123456,root:password,admin:admin,"
                 "admin:password,admin:admin123,user:user,test:test,"
                 "ubuntu:ubuntu,pi:raspberry,oracle:oracle,ftp:ftp")


def _weak_creds():
    raw = config.get("HONEYPOT_WEAK_CREDS", _DEFAULT_WEAK)
    out = {}
    for pair in raw.replace(";", ",").split(","):
        pair = pair.strip()
        if ":" in pair:
            u, p = pair.split(":", 1)
            out[(u.strip(), p.strip())] = True
    return out


WEAK = _weak_creds()


def _valid(username, password):
    return (username, password) in WEAK


def _flag(name, default="1"):
    return str(config.get(name, default)).lower() in ("1", "true", "yes", "on")


def _port(name, default):
    try:
        return int(config.get(name, default))
    except (TypeError, ValueError):
        return default


# --- shared logging ----------------------------------------------------------
# Feed the honeypot's own logger so service attacks land in the same stream as
# web attacks: same dashboard row per src_ip, same threat score, same alerts.

def _log(ip, event_type, category, payload, severity="high", extra=None,
         method="", path=""):
    headers = {}
    findings = [{"category": category, "field": "service:" + event_type,
                 "payload": payload, "severity": severity}] if category else []
    try:
        logger.log_event(
            remote_addr=ip, method=method or event_type.upper(),
            path=path or payload, query={}, form={}, headers=headers,
            findings=findings, event_type=event_type, extra=extra or {})
    except Exception as exc:
        print("[services] log failed: %s" % exc, flush=True)


# --- generic threaded listener ----------------------------------------------

def _serve(name, port, handler):
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((BIND, port))
        srv.listen(64)
    except OSError as exc:
        print(" ! %s honeypot could not bind %s:%s (%s)" % (name, BIND, port, exc), flush=True)
        return
    print(" * %s honeypot listening on %s:%s" % (name, BIND, port), flush=True)
    while True:
        try:
            client, addr = srv.accept()
        except OSError:
            continue
        t = threading.Thread(target=_guard, args=(handler, client, addr),
                             daemon=True, name="%s-%s" % (name, addr[0]))
        t.start()


def _guard(handler, client, addr):
    ip = addr[0]
    try:
        client.settimeout(30)
        handler(client, ip)
    except Exception:
        pass
    finally:
        try:
            client.close()
        except OSError:
            pass


# --- FTP ---------------------------------------------------------------------

def _ftp_handler(sock, ip):
    banner = config.get("HONEYPOT_FTP_BANNER", "vsFTPd 2.3.4")
    _log(ip, "ftp_connect", "", banner, severity="low")
    sock.sendall(("220 (%s)\r\n" % banner).encode())
    user = None
    attempts = 0
    authed = False
    while True:
        try:
            line = sock.recv(1024)
        except (socket.timeout, OSError):
            break
        if not line:
            break
        try:
            text = line.decode("utf-8", "replace").strip()
        except Exception:
            text = ""
        if not text:
            continue
        parts = text.split(" ", 1)
        cmd = parts[0].upper()
        arg = parts[1] if len(parts) > 1 else ""

        if cmd == "USER":
            user = arg
            # vsftpd 2.3.4 backdoor trigger: a username ending in ":)" opened a
            # root bind-shell on port 6200 in the real CVE. We detect the exact
            # Metasploit trigger and record it as an exploit attempt — no shell.
            if arg.endswith(":)"):
                _log(ip, "ftp_exploit", "lfi_rce_upload",
                     "vsftpd 2.3.4 backdoor trigger (username '%s')" % arg,
                     extra={"cve": "CVE-2011-2523", "service": "ftp"})
            sock.sendall(b"331 Please specify the password.\r\n")
        elif cmd == "PASS":
            attempts += 1
            ok = _valid(user or "", arg)
            _log(ip, "ftp_login", "brute_force",
                 "FTP %s:%s" % (user, arg),
                 extra={"service": "ftp", "username": user, "password": arg,
                        "success": ok, "attempt": attempts})
            if ok:
                authed = True
                sock.sendall(b"230 Login successful.\r\n")
            else:
                sock.sendall(b"530 Login incorrect.\r\n")
        elif cmd == "SYST":
            sock.sendall(b"215 UNIX Type: L8\r\n")
        elif cmd == "FEAT":
            sock.sendall(b"211-Features:\r\n PASV\r\n UTF8\r\n211 End\r\n")
        elif cmd == "PWD":
            sock.sendall(b'257 "/" is the current directory\r\n')
        elif cmd == "TYPE":
            sock.sendall(b"200 Switching to Binary mode.\r\n")
        elif cmd in ("LIST", "NLST", "RETR", "STOR", "PASV", "PORT", "CWD", "MLSD"):
            if authed:
                # We never open a data channel; a passive listing simply times
                # out for the client, which is fine — the credential is captured.
                _log(ip, "ftp_command", "brute_force", "FTP %s %s" % (cmd, arg),
                     severity="medium", extra={"service": "ftp", "command": text})
                sock.sendall(b"425 Use PASV first.\r\n" if cmd in ("LIST", "NLST", "RETR", "STOR")
                             else b"200 OK\r\n")
            else:
                sock.sendall(b"530 Please login with USER and PASS.\r\n")
        elif cmd == "QUIT":
            sock.sendall(b"221 Goodbye.\r\n")
            break
        else:
            sock.sendall(b"500 Unknown command.\r\n")
        if attempts > 5000:                       # bound a runaway brute-force
            break


# --- SSH (paramiko) ----------------------------------------------------------

_ssh_key = None


def _host_key():
    """Load or generate a stable SSH host key, so the fingerprint is constant."""
    global _ssh_key
    if _ssh_key is not None:
        return _ssh_key
    import paramiko
    keydir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "certs")
    path = os.path.join(keydir, "ssh_host_rsa_key")
    try:
        if os.path.exists(path):
            _ssh_key = paramiko.RSAKey(filename=path)
            return _ssh_key
    except Exception:
        pass
    _ssh_key = paramiko.RSAKey.generate(2048)
    try:
        os.makedirs(keydir, exist_ok=True)
        _ssh_key.write_private_key_file(path)
    except Exception:
        pass
    return _ssh_key


def _make_ssh_interface(ip):
    import paramiko

    class _Server(paramiko.ServerInterface):
        def __init__(self):
            self.event = threading.Event()
            self.user = None
            self.attempts = 0

        def check_channel_request(self, kind, chanid):
            if kind == "session":
                return paramiko.OPEN_SUCCEEDED
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        def check_auth_password(self, username, password):
            self.attempts += 1
            self.user = username
            ok = _valid(username, password)
            _log(ip, "ssh_login", "brute_force",
                 "SSH %s:%s" % (username, password),
                 extra={"service": "ssh", "username": username, "password": password,
                        "success": ok, "attempt": self.attempts})
            return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

        def check_auth_publickey(self, username, key):
            _log(ip, "ssh_login", "brute_force",
                 "SSH pubkey auth by %s" % username, severity="medium",
                 extra={"service": "ssh", "username": username, "method": "publickey"})
            return paramiko.AUTH_FAILED

        def get_allowed_auths(self, username):
            return "password,publickey"

        def check_channel_shell_request(self, channel):
            self.event.set()
            return True

        def check_channel_pty_request(self, channel, term, w, h, pw, ph, modes):
            return True

        def check_channel_exec_request(self, channel, command):
            # Non-interactive: `ssh host <cmd>`. Log it and answer once.
            try:
                cmd = command.decode("utf-8", "replace")
            except Exception:
                cmd = str(command)
            _log(ip, "ssh_command", "cmdi", "SSH exec: %s" % cmd,
                 extra={"service": "ssh", "command": cmd, "mode": "exec"})
            try:
                channel.sendall((_fake_output(cmd) + "\r\n").encode())
                channel.send_exit_status(0)
            except Exception:
                pass
            self.event.set()
            return True

    return _Server()


# A believable, fully static fake system. The richer this is, the longer an
# intruder explores and the more of their methodology we record — but NOTHING
# here is computed from attacker input, and no command touches the real host.
# Tempting bait files (private keys, DB creds, a password backup) are planted to
# see whether the attacker exfiltrates them.

_FAKE_FILES = {
    "/etc/passwd": ("root:x:0:0:root:/root:/bin/bash\r\n"
                    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n"
                    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\r\n"
                    "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin\r\n"
                    "postgres:x:112:119:PostgreSQL admin:/var/lib/postgresql:/bin/bash\r\n"
                    "portal:x:1000:1000:Portal App:/home/portal:/bin/bash"),
    "/etc/shadow": ("root:$6$rounds=656000$Yn3kd$2Jqf0Bq9Xz1mM8vN7pL...:19700:0:99999:7:::\r\n"
                    "portal:$6$mZ9x$8kQh2Vd6Nn4wR1sT...:19700:0:99999:7:::"),
    "/etc/hostname": "srv-portal",
    "/etc/os-release": ('PRETTY_NAME="Ubuntu 22.04.3 LTS"\r\nVERSION_ID="22.04"\r\n'
                        'ID=ubuntu\r\nVERSION_CODENAME=jammy'),
    "/root/.bash_history": ("ls -la\r\ncd /home/portal\r\ncat .env\r\n"
                            "mysql -u portal_app -p portal < backup.sql\r\n"
                            "systemctl restart nginx\r\nexit"),
    "/root/.ssh/id_rsa": ("-----BEGIN OPENSSH PRIVATE KEY-----\r\n"
                          "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdz\r\n"
                          "c2gtcnNhAAAAAwEAAQAAAYEA3Jd0k2h...DECOY...KEY...DO...NOT...USE\r\n"
                          "-----END OPENSSH PRIVATE KEY-----"),
    "/home/portal/.env": ("APP_ENV=production\r\nDB_HOST=127.0.0.1\r\nDB_NAME=portal\r\n"
                          "DB_USER=portal_app\r\nDB_PASS=P0rtal!DB_2024\r\n"
                          "SECRET_KEY=8f3c2a9e1b7d4f6a0c5e2d8b1a4f7c3e\r\n"
                          "SMTP_PASS=mail_decoy_pw_9931"),
    "/home/portal/backup.sql": ("-- MySQL dump 10.13\r\n-- Host: localhost    Database: portal\r\n"
                                "INSERT INTO users VALUES (1,'admin','$2y$10$decoyhash...');\r\n"
                                "-- (truncated)"),
    "/etc/crontab": ("SHELL=/bin/sh\r\n0 2 * * * root /opt/portal/backup.sh\r\n"
                     "*/5 * * * * portal /usr/bin/python3 /opt/portal/sync.py"),
}

_FAKE_DIRS = {
    "/root": "backup.sql  portal  students.csv",
    "/root/.ssh": "authorized_keys  id_rsa  id_rsa.pub  known_hosts",
    "/home": "portal",
    "/home/portal": "app  .env  backup.sql  logs  static",
    "/var/www": "html  portal",
    "/opt/portal": "backup.sh  sync.py  config.ini",
}

_FAKE_FS = {
    "whoami": "root",
    "id": "uid=0(root) gid=0(root) groups=0(root)",
    "uname": "Linux",
    "uname -a": "Linux srv-portal 5.15.0-91-generic #101-Ubuntu SMP Fri Jan 12 2024 x86_64 GNU/Linux",
    "hostname": "srv-portal",
    "pwd": "/root",
    "ls": "backup.sql  portal  students.csv",
    "ls -a": ".  ..  .bash_history  .bashrc  .profile  .ssh  backup.sql  portal  students.csv",
    "ls -la": ("total 56\r\ndrwx------  5 root root 4096 Jun 10 09:14 .\r\n"
               "drwxr-xr-x 22 root root 4096 May 02 11:03 ..\r\n"
               "-rw-------  1 root root 2304 Jun 10 09:14 .bash_history\r\n"
               "drwx------  2 root root 4096 May 02 11:03 .ssh\r\n"
               "-rw-r--r--  1 root root  571 Jan 12 2024 backup.sql\r\n"
               "drwxr-xr-x  8 root root 4096 Jun 09 22:41 portal\r\n"
               "-rw-r--r--  1 root root 8814 Jun 01 08:20 students.csv"),
    "ps": "  PID TTY          TIME CMD\r\n 1123 pts/0    00:00:00 bash\r\n 1190 pts/0    00:00:00 ps",
    "ps aux": ("USER     PID %CPU %MEM    VSZ   RSS COMMAND\r\n"
               "root       1  0.0  0.1 168280 11660 /sbin/init\r\n"
               "postgres 812  0.2  1.9 214888 78120 postgres: portal\r\n"
               "portal   955  0.1  0.9  98220 37440 python3 /opt/portal/app.py\r\n"
               "www-data 990  0.1  0.8 122440 33210 nginx: worker process"),
    "netstat -tlnp": ("Proto Local Address     State    PID/Program\r\n"
                      "tcp   0.0.0.0:22          LISTEN   712/sshd\r\n"
                      "tcp   0.0.0.0:80          LISTEN   990/nginx\r\n"
                      "tcp   127.0.0.1:5432      LISTEN   812/postgres\r\n"
                      "tcp   0.0.0.0:8080        LISTEN   955/python3"),
    "ifconfig": ("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n"
                 "        inet 10.0.14.7  netmask 255.255.255.0  broadcast 10.0.14.255\r\n"
                 "        ether 02:42:0a:00:0e:07  txqueuelen 1000  (Ethernet)"),
    "ip a": ("2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\r\n"
             "    inet 10.0.14.7/24 brd 10.0.14.255 scope global eth0"),
    "sudo -l": ("Matching Defaults entries for root on srv-portal:\r\n"
                "    env_reset, secure_path=/usr/sbin\r\nUser root may run the "
                "following commands on srv-portal:\r\n    (ALL : ALL) ALL"),
    "crontab -l": ("0 2 * * * /opt/portal/backup.sh\r\n"
                   "*/5 * * * * /usr/bin/python3 /opt/portal/sync.py"),
    "env": ("SHELL=/bin/bash\r\nUSER=root\r\nHOME=/root\r\nPWD=/root\r\n"
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
    "w": ("10:14:22 up 41 days,  3:02,  1 user,  load average: 0.08, 0.03, 0.01\r\n"
          "USER     TTY      FROM             LOGIN@   IDLE   WHAT\r\n"
          "root     pts/0    10.0.14.1        10:14    0.00s  -bash"),
    "df -h": ("Filesystem      Size  Used Avail Use% Mounted on\r\n"
              "/dev/sda1        79G   18G   57G  24% /\r\n"
              "tmpfs           3.9G     0  3.9G   0% /dev/shm"),
    "cat /etc/os-release": _FAKE_FILES["/etc/os-release"],
    "lsb_release -a": ("Distributor ID:\tUbuntu\r\nDescription:\tUbuntu 22.04.3 LTS\r\n"
                       "Release:\t22.04\r\nCodename:\tjammy"),
}


def _read_file(path):
    p = path.strip().strip('"').strip("'")
    if p in _FAKE_FILES:
        return _FAKE_FILES[p]
    # a couple of common relative forms from /root or /home/portal
    for base in ("/root/", "/home/portal/"):
        if _FAKE_FILES.get(base + p.lstrip("./")):
            return _FAKE_FILES[base + p.lstrip("./")]
    return None


def _fake_output(cmd):
    c = cmd.strip()
    low = c.lower()
    if c in _FAKE_FS:
        return _FAKE_FS[c]
    if low in _FAKE_FS:
        return _FAKE_FS[low]
    if low in ("exit", "logout", "quit"):
        return None
    if low.startswith(("cd", "export", "unset", "history -c", "clear", ":")):
        return ""
    if low == "history":
        return _FAKE_FILES["/root/.bash_history"]
    # file reads — the tempting part; hit a planted file or a clean 404
    for pre in ("cat ", "less ", "more ", "head ", "tail ", "nl ", "strings "):
        if low.startswith(pre):
            body = _read_file(c[len(pre):])
            return body if body is not None else "%s: No such file or directory" % c.split()[-1]
    # directory listings of known paths
    if low.startswith("ls "):
        target = c.split(" ", 1)[1].strip().strip('"').strip("'").split()[-1]
        if target in _FAKE_DIRS:
            return _FAKE_DIRS[target]
        if target in _FAKE_FILES:
            return target
        if target.startswith("-"):                 # ls with only flags -> cwd
            return _FAKE_FS["ls"]
        return "ls: cannot access '%s': No such file or directory" % target
    if low.startswith(("wget", "curl")):
        return "%s: unable to resolve host address" % low.split()[0]
    if low.startswith("find "):
        return "\r\n".join(sorted(_FAKE_FILES.keys())[:6])
    if low.startswith("grep "):
        return ""
    if low.startswith(("sudo", "su ")):
        return _FAKE_FS.get(low, "root@srv-portal:~# ")
    if low.startswith(("nano", "vi", "vim", "python", "perl", "nc", "ncat", "bash -i")):
        return ""                                  # swallow interactive tools quietly
    return "-bash: %s: command not found" % c.split(" ")[0]


def _fake_shell(chan, ip, user):
    prompt = "%s@srv-portal:~# " % (user or "root")
    try:
        chan.sendall(("Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n"
                      " * Last login: Mon Jun 10 09:14:22 2026 from 10.0.14.1\r\n\r\n").encode())
        chan.sendall(prompt.encode())
    except Exception:
        return
    buf = ""
    cmds = 0
    while True:
        try:
            data = chan.recv(1024)
        except (socket.timeout, Exception):
            break
        if not data:
            break
        try:
            text = data.decode("utf-8", "replace")
        except Exception:
            text = ""
        for ch in text:
            if ch in ("\r", "\n"):
                line = buf.strip()
                buf = ""
                try:
                    chan.sendall(b"\r\n")
                except Exception:
                    return
                if not line:
                    try: chan.sendall(prompt.encode())
                    except Exception: return
                    continue
                cmds += 1
                _log(ip, "ssh_command", "cmdi", "SSH shell: %s" % line,
                     extra={"service": "ssh", "command": line, "user": user, "mode": "shell"})
                out = _fake_output(line)
                if out is None:                    # exit / logout
                    try: chan.sendall(b"logout\r\n")
                    except Exception: pass
                    return
                try:
                    if out:
                        chan.sendall((out + "\r\n").encode())
                    chan.sendall(prompt.encode())
                except Exception:
                    return
                if cmds > 500:
                    return
            elif ch == "\x7f":                     # backspace
                buf = buf[:-1]
            elif ch == "\x03":                     # Ctrl-C
                buf = ""
                try: chan.sendall(("^C\r\n" + prompt).encode())
                except Exception: return
            else:
                buf += ch


def _ssh_handler(sock, ip):
    import paramiko
    banner = config.get("HONEYPOT_SSH_BANNER", "OpenSSH_8.9p1 Ubuntu-3ubuntu0.4")
    try:
        transport = paramiko.Transport(sock)
        transport.local_version = "SSH-2.0-" + banner
        transport.add_server_key(_host_key())
        server = _make_ssh_interface(ip)
        try:
            transport.start_server(server=server)
        except paramiko.SSHException:
            _log(ip, "ssh_connect", "scanner", "SSH handshake aborted (scan?)",
                 severity="low")
            return
        chan = transport.accept(20)
        if chan is None:
            transport.close()
            return
        server.event.wait(10)
        if server.event.is_set():
            _fake_shell(chan, ip, server.user)
        try:
            chan.close()
        except Exception:
            pass
        transport.close()
    except Exception:
        pass


# --- lifecycle ---------------------------------------------------------------

_started = False


def start():
    """Launch the enabled service listeners. Idempotent; call after any fork."""
    global _started
    if _started:
        return
    _started = True
    launched = []
    if _flag("HONEYPOT_FTP_ENABLE"):
        p = _port("HONEYPOT_FTP_PORT", 2121)
        threading.Thread(target=_serve, args=("FTP", p, _ftp_handler),
                         daemon=True, name="ftp-honeypot").start()
        launched.append("FTP:%d" % p)
    if _flag("HONEYPOT_SSH_ENABLE"):
        try:
            import paramiko  # noqa: F401
            p = _port("HONEYPOT_SSH_PORT", 2222)
            threading.Thread(target=_serve, args=("SSH", p, _ssh_handler),
                             daemon=True, name="ssh-honeypot").start()
            launched.append("SSH:%d" % p)
        except ImportError:
            print(" ! SSH honeypot disabled — 'paramiko' is not installed "
                  "(pip install paramiko)", flush=True)
    if launched:
        print(" * Service honeypots active: %s · %d weak credential pair(s) planted"
              % (", ".join(launched), len(WEAK)), flush=True)


def status():
    return {
        "ssh_enabled": _flag("HONEYPOT_SSH_ENABLE"),
        "ftp_enabled": _flag("HONEYPOT_FTP_ENABLE"),
        "ssh_port": _port("HONEYPOT_SSH_PORT", 2222),
        "ftp_port": _port("HONEYPOT_FTP_PORT", 2121),
        "weak_cred_pairs": len(WEAK),
        "started": _started,
    }
