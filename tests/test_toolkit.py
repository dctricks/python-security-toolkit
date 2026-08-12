import sys
from pathlib import Path
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import toolkit

def test_validate_ipv4():
    assert toolkit.validate_target("127.0.0.1") is True


def test_validate_localhost():
    assert toolkit.validate_target("localhost") is True


def test_validate_invalid_hostname():
    assert toolkit.validate_target("not a real target") is False


def test_check_port_open():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)

    port = server.getsockname()[1]

    try:
        assert toolkit.check_port("127.0.0.1", port) is True
    finally:
        server.close()


def test_check_port_closed():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))

    port = server.getsockname()[1]
    server.close()

    assert toolkit.check_port("127.0.0.1", port) is False


class SecurityTestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        )
        self.end_headers()

    def log_message(self, format, *args):
        pass


def test_check_headers():
    server = HTTPServer(("127.0.0.1", 0), SecurityTestHandler)
    port = server.server_address[1]

    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
    )
    thread.start()

    try:
        status, headers = toolkit.check_headers(
            f"http://127.0.0.1:{port}"
        )

        assert status == 200
        assert headers["Content-Security-Policy"] == "default-src 'self'"
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["X-Frame-Options"] == "DENY"
        assert headers["Referrer-Policy"] == (
            "strict-origin-when-cross-origin"
        )
        assert "Strict-Transport-Security" in headers

    finally:
        server.shutdown()
        server.server_close()


def test_analyze_security_headers(capsys):
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
    }

    toolkit.analyze_security_headers(headers)

    output = capsys.readouterr().out

    assert "[+] Content-Security-Policy: PRESENT" in output
    assert "[+] X-Content-Type-Options: PRESENT" in output
    assert "[+] X-Frame-Options: PRESENT" in output
    assert "[+] Referrer-Policy: PRESENT" in output
    assert "[-] Strict-Transport-Security: MISSING" in output
