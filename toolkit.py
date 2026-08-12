#!/usr/bin/env python3

import argparse
import ipaddress
import socket
import urllib.error
import urllib.request


def validate_target(target):
    """Return True if target is an IP address or resolvable hostname."""

    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    try:
        socket.getaddrinfo(target, None)
        return True
    except socket.gaierror:
        return False


def check_port(target, port, timeout=1):
    """Check whether a TCP port is accepting connections."""

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        return sock.connect_ex((target, port)) == 0
    except socket.error:
        return False
    finally:
        sock.close()


def check_headers(url, timeout=5):
    """Retrieve HTTP response headers from a URL."""

    request = urllib.request.Request(
        url,
        method="GET",
        headers={"User-Agent": "Python-Security-Toolkit/1.0"},
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, dict(response.headers)

    except (urllib.error.URLError, ValueError) as exc:
        return None, {"error": str(exc)}


def analyze_security_headers(headers):
    """Check for commonly recommended HTTP security headers."""

    recommended_headers = [
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Strict-Transport-Security",
    ]

    print()
    print("Security Headers")
    print("----------------")

    for header in recommended_headers:
        if header in headers:
            print(f"[+] {header}: PRESENT")
        else:
            print(f"[-] {header}: MISSING")


def main():
    parser = argparse.ArgumentParser(
        description="Python Security & Network Toolkit"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    validate_parser = subparsers.add_parser(
        "validate",
        help="Validate an IP address or hostname",
    )
    validate_parser.add_argument("target")

    check_parser = subparsers.add_parser(
        "check",
        help="Check TCP connectivity to a port",
    )
    check_parser.add_argument("target")
    check_parser.add_argument("port", type=int)

    headers_parser = subparsers.add_parser(
        "headers",
        help="Inspect HTTP response headers",
    )
    headers_parser.add_argument("url")

    args = parser.parse_args()

    if args.command == "validate":
        if validate_target(args.target):
            print(f"[+] Valid target: {args.target}")
        else:
            print(f"[-] Invalid target: {args.target}")

    elif args.command == "check":
        if not validate_target(args.target):
            print(f"[-] Invalid target: {args.target}")
            return

        if not 1 <= args.port <= 65535:
            print("[-] Port must be between 1 and 65535.")
            return

        if check_port(args.target, args.port):
            print(f"[+] {args.target}:{args.port} is OPEN")
        else:
            print(f"[-] {args.target}:{args.port} is CLOSED")

    elif args.command == "headers":
        status, headers = check_headers(args.url)

        if status is None:
            print(f"[-] Unable to retrieve headers: {headers['error']}")
            return

        print(f"[+] HTTP Status: {status}")
        print("[+] Response Headers:")

        for name, value in headers.items():
            print(f"    {name}: {value}")

        analyze_security_headers(headers)

if __name__ == "__main__":
    main()
