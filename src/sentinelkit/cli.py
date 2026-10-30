"""Command-line interface for safe, defensive security checks."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import platform
import re
import socket
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


SECURITY_HEADERS = {
    "strict-transport-security": "Encourages HTTPS connections",
    "content-security-policy": "Restricts browser content sources",
    "x-content-type-options": "Helps prevent MIME sniffing",
    "x-frame-options": "Helps reduce clickjacking risk",
    "referrer-policy": "Controls referrer information",
    "permissions-policy": "Restricts browser features",
}


def cmd_audit(_args: argparse.Namespace) -> int:
    """Print basic information about the current machine."""
    report = {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "effective_user": getpass.getuser(),
        "administrator_or_root": hasattr(os, "geteuid") and os.geteuid() == 0,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }
    print(json.dumps(report, indent=2))
    if sys.platform.startswith("linux"):
        checks = [
            (Path("/etc/passwd"), "World-writable /etc/passwd"),
            (Path("/etc/shadow"), "Shadow password file exists"),
        ]
        for path, label in checks:
            if path.exists():
                mode = path.stat().st_mode
                if path.name == "passwd" and mode & 0o002:
                    print(f"[WARN] {label}")
                elif path.name == "shadow":
                    print(f"[INFO] {label}; review its permissions locally.")
    return 0


def cmd_hash(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.is_file():
        print(f"Not a regular file: {path}", file=sys.stderr)
        return 2
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    print(f"SHA256  {digest.hexdigest()}  {path}")
    return 0


def cmd_headers(args: argparse.Namespace) -> int:
    parsed = urlparse(args.url)
    if parsed.scheme != "https" or not parsed.hostname:
        print("Provide a complete HTTPS URL, such as https://example.com", file=sys.stderr)
        return 2
    request = urllib.request.Request(args.url, method="GET", headers={"User-Agent": "SentinelKit/0.1"})
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            headers = {k.lower(): v for k, v in response.headers.items()}
            print(f"URL: {response.geturl()}")
            print(f"HTTP status: {response.status}")
            for name, purpose in SECURITY_HEADERS.items():
                value = headers.get(name)
                if value:
                    print(f"[OK]   {name}: {value}")
                else:
                    print(f"[INFO] {name}: not present ({purpose})")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(f"Request failed: {exc}", file=sys.stderr)
        return 1
    return 0


def cmd_tls(args: argparse.Namespace) -> int:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((args.host, args.port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=args.host) as conn:
                cert = conn.getpeercert()
                print(f"Host: {args.host}:{args.port}")
                print(f"TLS version: {conn.version()}")
                print(f"Cipher: {conn.cipher()[0] if conn.cipher() else 'unknown'}")
                print(f"Subject: {cert.get('subject', 'unknown')}")
                print(f"Issuer: {cert.get('issuer', 'unknown')}")
                print(f"Expires: {cert.get('notAfter', 'unknown')}")
    except (OSError, ssl.SSLError) as exc:
        print(f"TLS check failed: {exc}", file=sys.stderr)
        return 1
    return 0


def parse_ports(value: str) -> list[int]:
    ports: list[int] = []
    for part in value.split(","):
        try:
            port = int(part.strip())
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"Invalid port: {part}") from exc
        if not 1 <= port <= 65535:
            raise argparse.ArgumentTypeError(f"Port out of range: {port}")
        if port not in ports:
            ports.append(port)
    if not ports or len(ports) > 128:
        raise argparse.ArgumentTypeError("Specify between 1 and 128 distinct ports.")
    return ports


def cmd_ports(args: argparse.Namespace) -> int:
    """Check a small, explicit list of TCP ports on one authorized host."""
    try:
        addresses = socket.getaddrinfo(args.host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        print(f"Could not resolve host: {exc}", file=sys.stderr)
        return 1
    ip = addresses[0][4][0]
    print(f"Target: {args.host} ({ip})")
    print("Only use this check on systems you own or are authorized to test.")
    for port in args.ports:
        sock = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.6)
        try:
            result = sock.connect_ex((ip, port))
            state = "OPEN" if result == 0 else "not open / filtered"
            print(f"{port:5}  {state}")
        finally:
            sock.close()
    return 0


SUSPICIOUS_LOG_PATTERNS = [
    (re.compile(r"failed password|authentication failure", re.I), "Failed authentication"),
    (re.compile(r"sudo:.*(COMMAND=|authentication failure)", re.I), "Privilege escalation activity"),
    (re.compile(r"invalid user", re.I), "Unknown account login attempt"),
    (re.compile(r"accepted password|accepted publickey", re.I), "Successful remote authentication"),
]


def cmd_logs(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.is_file():
        print(f"Log file not found: {path}", file=sys.stderr)
        return 2
    count = 0
    try:
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            for line_number, line in enumerate(stream, 1):
                for pattern, label in SUSPICIOUS_LOG_PATTERNS:
                    if pattern.search(line):
                        print(f"{line_number}: [{label}] {line.rstrip()[:300]}")
                        count += 1
                        break
    except OSError as exc:
        print(f"Could not read log: {exc}", file=sys.stderr)
        return 1
    print(f"Review complete: {count} matching log entries.")
    return 0


def estimate_password(password: str) -> tuple[str, list[str]]:
    """Simple local heuristic; not a guarantee of password security."""
    suggestions: list[str] = []
    if len(password) < 12:
        suggestions.append("Use at least 12 characters; longer is generally better.")
    if not re.search(r"[a-z]", password):
        suggestions.append("Add lowercase letters.")
    if not re.search(r"[A-Z]", password):
        suggestions.append("Add uppercase letters.")
    if not re.search(r"\d", password):
        suggestions.append("Consider including numbers.")
    if not re.search(r"[^A-Za-z0-9]", password):
        suggestions.append("Consider including symbols.")
    if re.search(r"(.)\1{3,}", password):
        suggestions.append("Avoid long repeated-character sequences.")
    if re.search(r"password|qwerty|letmein|admin", password, re.I):
        suggestions.append("Avoid common words and predictable patterns.")
    if len(password) >= 16 and not suggestions:
        return "Good heuristic result", suggestions
    return ("Needs improvement" if suggestions else "Moderate heuristic result"), suggestions


def cmd_password(_args: argparse.Namespace) -> int:
    password = getpass.getpass("Enter a password to evaluate locally (input hidden): ")
    if not password:
        print("No password entered.")
        return 2
    rating, suggestions = estimate_password(password)
    print(rating)
    for suggestion in suggestions:
        print(f"- {suggestion}")
    print("This is a basic heuristic, not a password-cracking test. The input is not saved or transmitted.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentinelkit", description="Defensive cybersecurity toolkit")
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", help="Show basic local system security information")
    audit.set_defaults(func=cmd_audit)

    file_hash = sub.add_parser("hash", help="Calculate a file's SHA-256 hash")
    file_hash.add_argument("file")
    file_hash.set_defaults(func=cmd_hash)

    headers = sub.add_parser("headers", help="Review HTTPS security response headers")
    headers.add_argument("url")
    headers.set_defaults(func=cmd_headers)

    tls = sub.add_parser("tls", help="Inspect a host's TLS certificate")
    tls.add_argument("host")
    tls.add_argument("--port", type=int, default=443)
    tls.set_defaults(func=cmd_tls)

    ports = sub.add_parser("ports", help="Check explicitly selected TCP ports on one authorized host")
    ports.add_argument("host")
    ports.add_argument("--ports", type=parse_ports, default=parse_ports("22,80,443"))
    ports.set_defaults(func=cmd_ports)

    logs = sub.add_parser("logs", help="Review a local authentication log")
    logs.add_argument("file")
    logs.set_defaults(func=cmd_logs)

    password = sub.add_parser("password-check", help="Evaluate a password locally")
    password.set_defaults(func=cmd_password)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
