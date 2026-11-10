import io
import socket
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from network_safety import (  # noqa: E402
    UnsafeTargetError,
    connect_public_target,
    public_http_get,
    resolve_public_addresses,
)


def addrinfo(ip, family=socket.AF_INET):
    sockaddr = (ip, 443) if family == socket.AF_INET else (ip, 443, 0, 0)
    return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr)


class NetworkSafetyTests(unittest.TestCase):
    def test_rejects_private_ip_literal_without_dns_lookup(self):
        with patch("network_safety.socket.getaddrinfo") as getaddrinfo:
            with self.assertRaises(UnsafeTargetError):
                resolve_public_addresses("127.0.0.1", 443)
        getaddrinfo.assert_not_called()

    def test_rejects_private_dns_answer(self):
        with patch("network_safety.socket.getaddrinfo", return_value=[addrinfo("10.0.0.4")]):
            with self.assertRaises(UnsafeTargetError):
                resolve_public_addresses("scanner.example", 443)

    def test_rejects_mixed_public_and_private_dns_answers(self):
        answers = [addrinfo("8.8.8.8"), addrinfo("192.168.1.10")]
        with patch("network_safety.socket.getaddrinfo", return_value=answers):
            with self.assertRaises(UnsafeTargetError):
                resolve_public_addresses("scanner.example", 443)

    def test_connects_to_the_checked_ip_without_a_second_resolution(self):
        connection = Mock()
        answers = [addrinfo("8.8.8.8")]
        with (
            patch("network_safety.socket.getaddrinfo", return_value=answers) as getaddrinfo,
            patch("network_safety.socket.socket", return_value=connection),
        ):
            result = connect_public_target("scanner.example", 443)

        self.assertIs(result, connection)
        connection.connect.assert_called_once_with(("8.8.8.8", 443))
        getaddrinfo.assert_called_once()

    def test_http_probe_does_not_follow_redirect_and_limits_body(self):
        connection = Mock()
        connection.makefile.return_value = io.BytesIO(
            b"HTTP/1.1 302 Found\r\n"
            b"Location: http://127.0.0.1/admin\r\n"
            b"Content-Length: 20\r\n\r\n"
            b"abcdefghijklmnopqrst"
        )
        with (
            patch("network_safety.connect_public_target", return_value=connection) as connect,
            patch("network_safety.socket.getaddrinfo", return_value=[addrinfo("8.8.8.8")]),
        ):
            response = public_http_get("scanner.example", "http", max_body_bytes=8)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["location"], "http://127.0.0.1/admin")
        self.assertEqual(response.text, "abcdefgh")
        connect.assert_called_once_with("scanner.example", 80, timeout=5)
        self.assertIn(b"GET / HTTP/1.1", connection.sendall.call_args.args[0])
        connection.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
