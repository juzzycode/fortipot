import socket

from fortipot.bait.server import BaitServiceManager, build_dns_nxdomain_response
from fortipot.config import Settings


def test_bait_http_service_returns_banner() -> None:
    settings = Settings.model_validate(
        {
            "bait": {
                "enabled": True,
                "bind_host": "127.0.0.1",
                "http": {
                    "enabled": True,
                    "port": 0,
                    "banner": "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
                },
            }
        }
    )
    manager = BaitServiceManager(settings.bait)
    manager.start()
    try:
        port = manager.handles[0].server.server_address[1]
        with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
            sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            data = sock.recv(1024)
        assert b"HTTP/1.1 200 OK" in data
        assert b"hello" in data
    finally:
        manager.stop()


def test_dns_nxdomain_response_preserves_question() -> None:
    query = bytes.fromhex("123401000001000000000000076578616d706c6503636f6d0000010001")

    response = build_dns_nxdomain_response(query)

    assert response[:2] == b"\x12\x34"
    assert response[2:4] == b"\x81\x83"
    assert response[12:] == query[12:]
