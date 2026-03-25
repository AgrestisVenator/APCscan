import argparse
import concurrent.futures
import csv
import ftplib
import random
import os
import queue
import re
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Iterable


USERNAME = "apc"
PASSWORD = "apc"

SUCCESS_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"control console",
        r"main menu",
        r"schneider electric",
        r"american power conversion",
        r"network management card",
        r"network management card aos",
        r"smart-ups\s*&\s*matrix-ups\s*app",
        r"super user",
        r"the current password policy requires you to change your password",
        r"enter current password",
        r"[>#]\s*$",
    )
]

FAILURE_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"permission denied",
        r"authentication failed",
        r"access denied",
    )
]

ERROR_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"no matching host key type found",
        r"no matching key exchange method found",
        r"no matching cipher found",
        r"host key verification failed",
        r"connection timed out",
        r"no route to host",
        r"could not resolve",
        r"connection reset",
        r"connection refused",
    )
]

LOGIN_PROMPT_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"user\s*name\s*[:>]\s*$",
        r"login\s*name\s*[:>]\s*$",
        r"login\s*[:>]\s*$",
        r"username\s*[:>]\s*$",
    )
]

PASSWORD_PROMPT_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"password\s*[:>]\s*$",
    )
]

TELNET_ERROR_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"could not open connection",
        r"connect failed",
        r"connection refused",
    )
]

WEB_SUCCESS_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"schneider electric",
        r"american power conversion",
        r"apc",
        r"network management card",
        r"smart-ups",
        r"ups",
        r"change your password",
        r"enter current password",
    )
]

WEB_FAILURE_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"invalid login",
        r"invalid user name or password",
        r"please try again",
        r"invalid username",
        r"invalid password",
        r"account locked",
        r"bad login attempts exceeded",
    )
]


@dataclass
class PortCheckResult:
    open: bool
    detail: str
    reachable: bool


@dataclass
class CredentialResult:
    reachable: str
    port22_open: str
    status: str
    detail: str


class LoginFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.action = ""
        self.inputs: dict[str, str] = {}
        self.in_login_form = False

    def handle_starttag(self, tag: str, attrs) -> None:
        attr_map = dict(attrs)
        if tag == "form" and attr_map.get("method", "").lower() == "post":
            self.in_login_form = True
            self.action = attr_map.get("action", "")
        elif tag == "input" and self.in_login_form:
            name = attr_map.get("name")
            if name:
                self.inputs[name] = attr_map.get("value", "")

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self.in_login_form:
            self.in_login_form = False


RETRYABLE_STATUSES = {"TIMEOUT", "UNKNOWN"}
FALLBACK_CONTINUE_STATUSES = {
    "PORT_CLOSED",
    "PORT23_CLOSED",
    "HTTPS_PORT_CLOSED",
    "HTTP_PORT_CLOSED",
    "FTP_PORT_CLOSED",
    "UNREACHABLE",
    "ERROR",
    "TIMEOUT",
    "UNKNOWN",
}
PROTOCOL_ORDER = ["ssh", "telnet", "https", "http", "ftp"]
RESULT_FIELDS = [
    "timestamp",
    "ip",
    "dns_name",
    "reachable",
    "port22_open",
    "status",
    "detail",
    "ssh_status",
    "ssh_detail",
    "telnet_status",
    "telnet_detail",
    "https_status",
    "https_detail",
    "http_status",
    "http_detail",
    "ftp_status",
    "ftp_detail",
]


def get_trimmed_preview(text: str, max_length: int = 200) -> str:
    if not text or not text.strip():
        return ""
    single_line = re.sub(r"\s+", " ", text).strip()
    return single_line[:max_length]


def protocol_detail(protocol: str, message: str) -> str:
    return f"{protocol}: {message}"


def test_tcp_port(ip: str, port: int, timeout_ms: int) -> PortCheckResult:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_ms / 1000)
    try:
        sock.connect((ip, port))
        return PortCheckResult(
            open=True,
            detail=f"TCP connect to port {port} succeeded",
            reachable=True,
        )
    except socket.timeout:
        return PortCheckResult(
            open=False,
            detail="Connection timeout",
            reachable=False,
        )
    except OSError as exc:
        message = str(exc)
        reachable = not re.search(r"timed out|host not found|unreachable", message, re.IGNORECASE)
        return PortCheckResult(open=False, detail=message, reachable=reachable)
    finally:
        sock.close()


def make_askpass_script(password: str) -> str:
    fd, path = tempfile.mkstemp(prefix="apc_ssh_askpass_", suffix=".cmd", text=True)
    os.close(fd)
    Path(path).write_text(f"@echo off\r\necho {password}\r\n", encoding="ascii")
    return path


def ssh_command(ip: str, connect_timeout_ms: int) -> list[str]:
    connect_timeout_seconds = max(int((connect_timeout_ms + 999) / 1000), 1)
    return [
        "ssh.exe",
        "-tt",
        "-o",
        "BatchMode=no",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=NUL",
        "-o",
        "PreferredAuthentications=password,keyboard-interactive",
        "-o",
        "PubkeyAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=yes",
        "-o",
        "PasswordAuthentication=yes",
        "-o",
        "NumberOfPasswordPrompts=1",
        "-o",
        "HostKeyAlgorithms=+ssh-rsa",
        "-o",
        "PubkeyAcceptedAlgorithms=+ssh-rsa",
        "-o",
        "KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1",
        "-o",
        "Ciphers=+aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc",
        "-o",
        "MACs=+hmac-sha1,hmac-md5",
        "-o",
        f"ConnectTimeout={connect_timeout_seconds}",
        "-l",
        USERNAME,
        ip,
    ]


def telnet_command(ip: str) -> list[str]:
    return ["telnet.exe", ip, "23"]


def make_legacy_ssl_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if hasattr(ssl, "TLSVersion"):
        context.minimum_version = ssl.TLSVersion.TLSv1
    try:
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    return context


def build_opener_for_scheme(scheme: str):
    handlers = [urllib.request.HTTPCookieProcessor()]
    if scheme == "https":
        handlers.append(urllib.request.HTTPSHandler(context=make_legacy_ssl_context()))
    return urllib.request.build_opener(*handlers)


def parse_login_form(html: str) -> tuple[str, dict[str, str]]:
    parser = LoginFormParser()
    parser.feed(html)
    return parser.action, parser.inputs


def matches_any(text: str, patterns: Iterable[re.Pattern[str]]) -> bool:
    return any(pattern.search(text) for pattern in patterns)


def start_reader_thread(stream, output_queue: "queue.Queue[str]") -> threading.Thread:
    def reader() -> None:
        try:
            for line in iter(stream.readline, ""):
                if not line:
                    break
                output_queue.put(line)
        finally:
            stream.close()

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    return thread


def test_apc_ssh_credential(ip: str, connect_timeout_ms: int, ssh_timeout_ms: int) -> CredentialResult:
    port_check = test_tcp_port(ip, 22, connect_timeout_ms)
    if not port_check.open:
        return CredentialResult(
            reachable="true" if port_check.reachable else "false",
            port22_open="false",
            status="PORT_CLOSED" if port_check.reachable else "UNREACHABLE",
            detail=protocol_detail("SSH", port_check.detail),
        )

    askpass_path = make_askpass_script(PASSWORD)
    process = None
    try:
        env = os.environ.copy()
        env["SSH_ASKPASS"] = askpass_path
        env["SSH_ASKPASS_REQUIRE"] = "force"
        env["DISPLAY"] = "1"

        process = subprocess.Popen(
            ssh_command(ip, connect_timeout_ms),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )

        output_queue: queue.Queue[str] = queue.Queue()
        stdout_thread = start_reader_thread(process.stdout, output_queue)
        stderr_thread = start_reader_thread(process.stderr, output_queue)
        chunks: list[str] = []
        deadline = time.monotonic() + (ssh_timeout_ms / 1000)

        while time.monotonic() < deadline:
            while True:
                try:
                    chunks.append(output_queue.get_nowait())
                except queue.Empty:
                    break

            preview = get_trimmed_preview("".join(chunks))
            if matches_any(preview, FAILURE_PATTERNS):
                process.kill()
                process.wait(timeout=2)
                return CredentialResult("true", "true", "AUTH_FAILED", protocol_detail("SSH", "Login rejected"))
            if matches_any(preview, ERROR_PATTERNS):
                process.kill()
                process.wait(timeout=2)
                return CredentialResult("true", "true", "ERROR", protocol_detail("SSH", preview))
            if matches_any(preview, SUCCESS_PATTERNS):
                process.kill()
                process.wait(timeout=2)
                return CredentialResult("true", "true", "SUCCESS", protocol_detail("SSH", "Authenticated with apc/apc"))

            if process.poll() is not None:
                break

            time.sleep(0.1)

        while True:
            try:
                chunks.append(output_queue.get_nowait())
            except queue.Empty:
                break

        stdout_thread.join(timeout=0.5)
        stderr_thread.join(timeout=0.5)
        combined = "".join(chunks)
        preview = get_trimmed_preview(combined)

        if process.poll() is None:
            process.kill()
            process.wait(timeout=2)
            if matches_any(preview, FAILURE_PATTERNS):
                return CredentialResult("true", "true", "AUTH_FAILED", protocol_detail("SSH", "Login rejected"))
            preview = get_trimmed_preview(combined)
            if matches_any(preview, ERROR_PATTERNS):
                return CredentialResult("true", "true", "ERROR", protocol_detail("SSH", preview))
            if matches_any(preview, SUCCESS_PATTERNS):
                return CredentialResult("true", "true", "SUCCESS", protocol_detail("SSH", "Authenticated with apc/apc"))
            return CredentialResult(
                "true",
                "true",
                "TIMEOUT",
                protocol_detail("SSH", preview or "Timed out waiting for APC SSH console banner or prompt"),
            )

        if process.returncode == 0:
            return CredentialResult("true", "true", "SUCCESS", protocol_detail("SSH", "Authenticated with apc/apc"))
        if matches_any(preview, FAILURE_PATTERNS):
            return CredentialResult("true", "true", "AUTH_FAILED", protocol_detail("SSH", "Login rejected"))
        if matches_any(preview, ERROR_PATTERNS):
            return CredentialResult("true", "true", "ERROR", protocol_detail("SSH", preview))
        if matches_any(preview, SUCCESS_PATTERNS):
            return CredentialResult("true", "true", "SUCCESS", protocol_detail("SSH", "Authenticated with apc/apc"))

        detail = protocol_detail("SSH", preview or f"ssh.exe exited with code {process.returncode}")
        return CredentialResult("true", "true", "UNKNOWN", detail)
    except Exception as exc:
        return CredentialResult(
            reachable="true" if port_check.reachable else "false",
            port22_open="true",
            status="ERROR",
            detail=protocol_detail("SSH", str(exc)),
        )
    finally:
        if process is not None and process.poll() is None:
            process.kill()
        try:
            os.remove(askpass_path)
        except OSError:
            pass


def test_apc_telnet_credential(ip: str, connect_timeout_ms: int, ssh_timeout_ms: int) -> CredentialResult:
    port_check = test_tcp_port(ip, 23, connect_timeout_ms)
    if not port_check.open:
        return CredentialResult(
            reachable="true" if port_check.reachable else "false",
            port22_open="false",
            status="PORT23_CLOSED" if port_check.reachable else "UNREACHABLE",
            detail=protocol_detail("TELNET", port_check.detail),
        )

    process = None
    try:
        process = subprocess.Popen(
            telnet_command(ip),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )

        output_queue: queue.Queue[str] = queue.Queue()
        stdout_thread = start_reader_thread(process.stdout, output_queue)
        stderr_thread = start_reader_thread(process.stderr, output_queue)
        chunks: list[str] = []
        deadline = time.monotonic() + (ssh_timeout_ms / 1000)
        username_sent = False
        password_sent = False
        login_prompt_seen = False

        while time.monotonic() < deadline:
            while True:
                try:
                    chunks.append(output_queue.get_nowait())
                except queue.Empty:
                    break

            preview = get_trimmed_preview("".join(chunks))
            has_login_prompt = matches_any(preview, LOGIN_PROMPT_PATTERNS)
            has_password_prompt = matches_any(preview, PASSWORD_PROMPT_PATTERNS)

            if has_login_prompt and password_sent:
                process.kill()
                process.wait(timeout=2)
                return CredentialResult("true", "false", "AUTH_FAILED", protocol_detail("TELNET", "Login rejected"))

            if not username_sent and has_login_prompt:
                process.stdin.write(f"{USERNAME}\r\n")
                process.stdin.flush()
                username_sent = True
                login_prompt_seen = True

            if username_sent and not password_sent and has_password_prompt:
                process.stdin.write(f"{PASSWORD}\r\n")
                process.stdin.flush()
                password_sent = True

            if matches_any(preview, FAILURE_PATTERNS):
                process.kill()
                process.wait(timeout=2)
                return CredentialResult("true", "false", "AUTH_FAILED", protocol_detail("TELNET", "Login rejected"))
            if matches_any(preview, TELNET_ERROR_PATTERNS):
                process.kill()
                process.wait(timeout=2)
                return CredentialResult("true", "false", "ERROR", protocol_detail("TELNET", preview))
            if matches_any(preview, SUCCESS_PATTERNS):
                process.kill()
                process.wait(timeout=2)
                return CredentialResult("true", "false", "SUCCESS", protocol_detail("TELNET", "Authenticated with apc/apc"))

            if process.poll() is not None:
                break

            time.sleep(0.1)

        while True:
            try:
                chunks.append(output_queue.get_nowait())
            except queue.Empty:
                break

        stdout_thread.join(timeout=0.5)
        stderr_thread.join(timeout=0.5)
        combined = "".join(chunks)
        preview = get_trimmed_preview(combined)

        if process.poll() is None:
            process.kill()
            process.wait(timeout=2)
            if login_prompt_seen and password_sent and matches_any(preview, LOGIN_PROMPT_PATTERNS):
                return CredentialResult("true", "false", "AUTH_FAILED", protocol_detail("TELNET", "Login rejected"))
            if matches_any(preview, FAILURE_PATTERNS):
                return CredentialResult("true", "false", "AUTH_FAILED", protocol_detail("TELNET", "Login rejected"))
            if matches_any(preview, TELNET_ERROR_PATTERNS):
                return CredentialResult("true", "false", "ERROR", protocol_detail("TELNET", preview))
            if matches_any(preview, SUCCESS_PATTERNS):
                return CredentialResult("true", "false", "SUCCESS", protocol_detail("TELNET", "Authenticated with apc/apc"))
            return CredentialResult(
                "true",
                "false",
                "TIMEOUT",
                protocol_detail("TELNET", preview or "Timed out waiting for APC Telnet console banner or prompt"),
            )

        if process.returncode == 0 and matches_any(preview, SUCCESS_PATTERNS):
            return CredentialResult("true", "false", "SUCCESS", protocol_detail("TELNET", "Authenticated with apc/apc"))
        if login_prompt_seen and password_sent and matches_any(preview, LOGIN_PROMPT_PATTERNS):
            return CredentialResult("true", "false", "AUTH_FAILED", protocol_detail("TELNET", "Login rejected"))
        if matches_any(preview, FAILURE_PATTERNS):
            return CredentialResult("true", "false", "AUTH_FAILED", protocol_detail("TELNET", "Login rejected"))
        if matches_any(preview, TELNET_ERROR_PATTERNS):
            return CredentialResult("true", "false", "ERROR", protocol_detail("TELNET", preview))
        if matches_any(preview, SUCCESS_PATTERNS):
            return CredentialResult("true", "false", "SUCCESS", protocol_detail("TELNET", "Authenticated with apc/apc"))

        detail = protocol_detail("TELNET", preview or f"telnet.exe exited with code {process.returncode}")
        return CredentialResult("true", "false", "UNKNOWN", detail)
    except Exception as exc:
        return CredentialResult(
            reachable="true" if port_check.reachable else "false",
            port22_open="false",
            status="ERROR",
            detail=protocol_detail("TELNET", str(exc)),
        )
    finally:
        if process is not None and process.poll() is None:
            process.kill()


def test_apc_web_credential(ip: str, scheme: str, connect_timeout_ms: int) -> CredentialResult:
    protocol = scheme.upper()
    port = 443 if scheme == "https" else 80
    port_check = test_tcp_port(ip, port, connect_timeout_ms)
    if not port_check.open:
        return CredentialResult(
            reachable="true" if port_check.reachable else "false",
            port22_open="false",
            status=f"{protocol}_PORT_CLOSED" if port_check.reachable else "UNREACHABLE",
            detail=protocol_detail(protocol, port_check.detail),
        )

    base_url = f"{scheme}://{ip}/"
    opener = build_opener_for_scheme(scheme)
    headers = {"User-Agent": "Mozilla/5.0 APC Credential Check"}

    try:
        login_request = urllib.request.Request(base_url, headers=headers)
        with opener.open(login_request, timeout=connect_timeout_ms / 1000) as response:
            login_html = response.read(8192).decode("utf-8", errors="replace")

        action, form_inputs = parse_login_form(login_html)
        if not action:
            preview = get_trimmed_preview(login_html)
            if matches_any(preview, WEB_SUCCESS_PATTERNS):
                return CredentialResult("true", "false", "SUCCESS", protocol_detail(protocol, "Authenticated with apc/apc"))
            return CredentialResult("true", "false", "ERROR", protocol_detail(protocol, "Login form not found"))

        post_url = urllib.parse.urljoin(base_url, action)
        form_inputs["login_username"] = USERNAME
        form_inputs["login_password"] = PASSWORD
        if "prefLanguage" in form_inputs and not form_inputs["prefLanguage"]:
            form_inputs["prefLanguage"] = "00000000"
        form_inputs.setdefault("submit", "Log On")

        encoded_body = urllib.parse.urlencode(form_inputs).encode("ascii")
        post_request = urllib.request.Request(post_url, data=encoded_body, headers=headers, method="POST")

        with opener.open(post_request, timeout=connect_timeout_ms / 1000) as response:
            final_url = response.geturl()
            body = response.read(8192).decode("utf-8", errors="replace")
            preview = get_trimmed_preview(body)

        if re.search(r"/home\.htm(?:[?#]|$)", final_url, re.IGNORECASE):
            return CredentialResult("true", "false", "SUCCESS", protocol_detail(protocol, "Authenticated with apc/apc"))
        if re.search(r"/pwchange\.htm(?:[?#]|$)", final_url, re.IGNORECASE):
            return CredentialResult("true", "false", "SUCCESS", protocol_detail(protocol, "Authenticated with apc/apc (password change required)"))
        if matches_any(preview, WEB_FAILURE_PATTERNS):
            return CredentialResult("true", "false", "AUTH_FAILED", protocol_detail(protocol, "Login rejected"))
        if re.search(r"/password(?:[?#]|$)", final_url, re.IGNORECASE):
            return CredentialResult("true", "false", "AUTH_FAILED", protocol_detail(protocol, f"Login redirected to {final_url}"))
        if matches_any(preview, WEB_SUCCESS_PATTERNS):
            return CredentialResult("true", "false", "SUCCESS", protocol_detail(protocol, "Authenticated with apc/apc"))

        return CredentialResult("true", "false", "UNKNOWN", protocol_detail(protocol, f"Login ended at {final_url}"))
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            return CredentialResult("true", "false", "AUTH_FAILED", protocol_detail(protocol, "Login rejected"))

        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        preview = get_trimmed_preview(body)
        detail = protocol_detail(protocol, preview or f"Returned status {exc.code}")
        return CredentialResult("true", "false", "ERROR", detail)
    except urllib.error.URLError as exc:
        detail = str(exc.reason)
        return CredentialResult("true", "false", "ERROR", protocol_detail(protocol, detail))
    except ssl.SSLError as exc:
        return CredentialResult("true", "false", "ERROR", protocol_detail(protocol, str(exc)))
    except Exception as exc:
        return CredentialResult("true", "false", "ERROR", protocol_detail(protocol, str(exc)))


def test_apc_ftp_credential(ip: str, connect_timeout_ms: int) -> CredentialResult:
    port_check = test_tcp_port(ip, 21, connect_timeout_ms)
    if not port_check.open:
        return CredentialResult(
            reachable="true" if port_check.reachable else "false",
            port22_open="false",
            status="FTP_PORT_CLOSED" if port_check.reachable else "UNREACHABLE",
            detail=protocol_detail("FTP", port_check.detail),
        )

    ftp = ftplib.FTP()
    ftp.timeout = connect_timeout_ms / 1000
    try:
        ftp.connect(ip, 21, timeout=connect_timeout_ms / 1000)
        ftp.login(USERNAME, PASSWORD)
        return CredentialResult("true", "false", "SUCCESS", protocol_detail("FTP", "Authenticated with apc/apc"))
    except ftplib.error_perm as exc:
        detail = str(exc)
        if detail.startswith("230"):
            return CredentialResult("true", "false", "SUCCESS", protocol_detail("FTP", "Authenticated with apc/apc"))
        return CredentialResult("true", "false", "AUTH_FAILED", protocol_detail("FTP", f"Login rejected: {detail}"))
    except ftplib.all_errors + (OSError,) as exc:
        detail = str(exc)
        if re.search(r"230\b|logged in", detail, re.IGNORECASE):
            return CredentialResult("true", "false", "SUCCESS", protocol_detail("FTP", "Authenticated with apc/apc"))
        return CredentialResult("true", "false", "ERROR", protocol_detail("FTP", detail))
    finally:
        try:
            ftp.quit()
        except Exception:
            try:
                ftp.close()
            except Exception:
                pass


def load_ips(input_file: Path) -> list[str]:
    if not input_file.exists():
        raise FileNotFoundError(f"Input file not found: {input_file}")

    ips = []
    for line in input_file.read_text(encoding="utf-8").splitlines():
        value = line.strip()
        if value and not value.startswith("#"):
            ips.append(value)
    return ips


def load_completed_ips(output_file: Path) -> set[str]:
    if not output_file.exists():
        return set()

    completed: set[str] = set()
    with output_file.open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or "ip" not in reader.fieldnames:
            return set()
        for row in reader:
            ip = (row.get("ip") or "").strip()
            if ip:
                completed.add(ip)
    return completed


def output_has_expected_header(output_file: Path) -> bool:
    if not output_file.exists() or output_file.stat().st_size == 0:
        return True

    with output_file.open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.reader(handle)
        try:
            header = next(reader)
        except StopIteration:
            return True
    return header == RESULT_FIELDS


def lookup_dns_name(ip: str) -> str:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except OSError:
        return ""


def empty_attempt_map() -> dict[str, CredentialResult]:
    return {
        protocol: CredentialResult("false", "false", "NOT_TRIED", f"{protocol.upper()}: Not tried")
        for protocol in PROTOCOL_ORDER
    }


def result_to_row(ip: str, final_result: CredentialResult, attempts: dict[str, CredentialResult]) -> dict[str, str]:
    row = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ip": ip,
        "dns_name": lookup_dns_name(ip),
        "reachable": final_result.reachable,
        "port22_open": final_result.port22_open,
        "status": final_result.status,
        "detail": final_result.detail,
    }
    for protocol in PROTOCOL_ORDER:
        attempt = attempts[protocol]
        row[f"{protocol}_status"] = attempt.status
        row[f"{protocol}_detail"] = attempt.detail
    return row


def should_continue_fallback(result: CredentialResult) -> bool:
    return result.status in FALLBACK_CONTINUE_STATUSES


def protocol_fallback_result(
    ip: str,
    connect_timeout_ms: int,
    ssh_timeout_ms: int,
) -> tuple[CredentialResult, dict[str, CredentialResult]]:
    attempts = empty_attempt_map()

    ssh_result = test_apc_ssh_credential(ip, connect_timeout_ms, ssh_timeout_ms)
    attempts["ssh"] = ssh_result
    if not should_continue_fallback(ssh_result):
        return ssh_result, attempts

    telnet_result = test_apc_telnet_credential(ip, connect_timeout_ms, ssh_timeout_ms)
    attempts["telnet"] = telnet_result
    if not should_continue_fallback(telnet_result):
        return telnet_result, attempts

    https_result = test_apc_web_credential(ip, "https", connect_timeout_ms)
    attempts["https"] = https_result
    if not should_continue_fallback(https_result):
        return https_result, attempts

    http_result = test_apc_web_credential(ip, "http", connect_timeout_ms)
    attempts["http"] = http_result
    if not should_continue_fallback(http_result):
        return http_result, attempts

    ftp_result = test_apc_ftp_credential(ip, connect_timeout_ms)
    attempts["ftp"] = ftp_result
    return ftp_result, attempts


def process_ip_with_fallbacks(
    ip: str,
    connect_timeout_ms: int,
    delay_ms: int,
    ssh_timeout_ms: int,
    retry_count: int,
    retry_delay_ms: int,
    jitter_ms: int,
) -> dict[str, str]:
    attempts = retry_count + 1
    row: dict[str, str] | None = None

    if jitter_ms > 0:
        time.sleep(random.uniform(0, jitter_ms) / 1000)

    for attempt in range(1, attempts + 1):
        final_result, attempt_map = protocol_fallback_result(ip, connect_timeout_ms, ssh_timeout_ms)
        row = result_to_row(ip, final_result, attempt_map)

        if row["status"] not in RETRYABLE_STATUSES or attempt == attempts:
            break

        if retry_delay_ms > 0:
            time.sleep(retry_delay_ms / 1000)

    if delay_ms > 0:
        time.sleep(delay_ms / 1000)

    return row


def write_results(
    ips: list[str],
    output_file: Path,
    connect_timeout_ms: int,
    delay_ms: int,
    ssh_timeout_ms: int,
    max_workers: int,
    resume: bool,
    retry_count: int,
    retry_delay_ms: int,
    jitter_ms: int,
) -> None:
    completed_ips = load_completed_ips(output_file) if resume else set()
    pending_ips = [ip for ip in ips if ip not in completed_ips]

    if resume and not output_has_expected_header(output_file):
        raise ValueError(
            f"Output file schema does not match current script: {output_file}. "
            "Start a new output file or remove --resume."
        )

    if resume and completed_ips:
        print(f"Resume mode: skipping {len(ips) - len(pending_ips)} IPs already present in {output_file}")

    if not pending_ips:
        print("No pending IPs to process.")
        return

    file_exists = output_file.exists()
    write_header = not (resume and file_exists and file_exists and output_file.stat().st_size > 0)
    mode = "a" if resume and file_exists else "w"

    with output_file.open(mode, newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=RESULT_FIELDS,
        )
        if write_header:
            writer.writeheader()
            handle.flush()

        total = len(pending_ips)
        completed = 0
        progress_interval = 25 if total >= 100 else 10

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(
                    process_ip_with_fallbacks,
                    ip,
                    connect_timeout_ms,
                    delay_ms,
                    ssh_timeout_ms,
                    retry_count,
                    retry_delay_ms,
                    jitter_ms,
                ): ip
                for ip in pending_ips
            }

            for future in concurrent.futures.as_completed(futures):
                ip = futures[future]
                try:
                    row = future.result()
                except Exception as exc:
                    row = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "ip": ip,
                        "dns_name": lookup_dns_name(ip),
                        "reachable": "false",
                        "port22_open": "false",
                        "status": "ERROR",
                        "detail": protocol_detail("WORKER", str(exc)),
                    }
                    for protocol in PROTOCOL_ORDER:
                        row[f"{protocol}_status"] = "NOT_TRIED"
                        row[f"{protocol}_detail"] = f"{protocol.upper()}: Not tried"

                writer.writerow(row)
                handle.flush()
                completed += 1
                print(f"{row['ip']} {row['status']} {row['detail']}")
                if completed == total or completed % progress_interval == 0:
                    print(f"Progress: {completed}/{total} completed")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-file", default="ips.txt")
    parser.add_argument("--output-file", default="apc_ssh_results.csv")
    parser.add_argument("--connect-timeout-ms", type=int, default=4000)
    parser.add_argument("--delay-ms", type=int, default=300)
    parser.add_argument("--ssh-timeout-ms", type=int, default=6000)
    parser.add_argument("--max-workers", type=int, default=20)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--retry-count", type=int, default=1)
    parser.add_argument("--retry-delay-ms", type=int, default=500)
    parser.add_argument("--jitter-ms", type=int, default=750)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    script_dir = Path(__file__).resolve().parent
    input_file = (script_dir / args.input_file).resolve()
    output_file = (script_dir / args.output_file).resolve()

    ips = load_ips(input_file)
    write_results(
        ips=ips,
        output_file=output_file,
        connect_timeout_ms=args.connect_timeout_ms,
        delay_ms=args.delay_ms,
        ssh_timeout_ms=args.ssh_timeout_ms,
        max_workers=max(args.max_workers, 1),
        resume=args.resume,
        retry_count=max(args.retry_count, 0),
        retry_delay_ms=max(args.retry_delay_ms, 0),
        jitter_ms=max(args.jitter_ms, 0),
    )
    print()
    print(f"Done. Results written to {output_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
