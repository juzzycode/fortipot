"""Honeyd-style bait service responders."""

from __future__ import annotations

import socketserver
import threading
from dataclasses import dataclass

from fortipot.config import BaitConfig
from fortipot.logging_utils import get_logger

logger = get_logger(__name__)


@dataclass
class BaitServiceSpec:
    """One concrete bait listener definition."""

    name: str
    protocol: str
    bind_host: str
    port: int
    banner: bytes = b""


@dataclass
class BaitServiceHandle:
    """Running bait service handle."""

    spec: BaitServiceSpec
    server: socketserver.BaseServer
    thread: threading.Thread


class _ThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _ThreadingUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class BaitServiceManager:
    """Manage a set of bait listeners."""

    def __init__(self, config: BaitConfig) -> None:
        self.config = config
        self.handles: list[BaitServiceHandle] = []

    def start(self) -> None:
        """Start enabled bait listeners."""

        for spec in build_bait_specs(self.config):
            handle = _start_service(spec)
            self.handles.append(handle)
            logger.info(
                "bait_service_started",
                service=spec.name,
                protocol=spec.protocol,
                bind_host=spec.bind_host,
                port=handle.server.server_address[1],
            )

    def stop(self) -> None:
        """Stop all bait listeners."""

        for handle in reversed(self.handles):
            handle.server.shutdown()
            handle.server.server_close()
            handle.thread.join(timeout=1)
            logger.info("bait_service_stopped", service=handle.spec.name, port=handle.server.server_address[1])
        self.handles.clear()


def build_bait_specs(config: BaitConfig) -> list[BaitServiceSpec]:
    """Return enabled bait listener specs."""

    if not config.enabled:
        return []
    specs: list[BaitServiceSpec] = []
    if config.http.enabled:
        specs.append(
            BaitServiceSpec("http", "tcp", config.bind_host, config.http.port, config.http.banner.encode("utf-8"))
        )
    if config.ssh.enabled:
        specs.append(
            BaitServiceSpec("ssh", "tcp", config.bind_host, config.ssh.port, config.ssh.banner.encode("utf-8"))
        )
    if config.dns.enabled:
        specs.append(BaitServiceSpec("dns", "udp", config.bind_host, config.dns.port))
    if config.samba.enabled:
        specs.append(
            BaitServiceSpec(
                "samba",
                "tcp",
                config.bind_host,
                config.samba.port,
                config.samba.banner.encode("latin-1", errors="ignore"),
            )
        )
    return specs


def _start_service(spec: BaitServiceSpec) -> BaitServiceHandle:
    if spec.protocol == "tcp":
        handler = _tcp_handler(spec)
        server = _ThreadingTCPServer((spec.bind_host, spec.port), handler)
    else:
        handler = _dns_handler()
        server = _ThreadingUDPServer((spec.bind_host, spec.port), handler)
    thread = threading.Thread(target=server.serve_forever, name=f"bait-{spec.name}", daemon=True)
    thread.start()
    return BaitServiceHandle(spec=spec, server=server, thread=thread)


def _tcp_handler(spec: BaitServiceSpec):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            try:
                self.request.settimeout(1)
                try:
                    self.request.recv(1024)
                except OSError:
                    pass
                if spec.banner:
                    self.request.sendall(spec.banner)
            finally:
                try:
                    self.request.close()
                except OSError:
                    pass

    return Handler


def _dns_handler():
    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            data, sock = self.request
            response = build_dns_nxdomain_response(data)
            if response:
                sock.sendto(response, self.client_address)

    return Handler


def build_dns_nxdomain_response(query: bytes) -> bytes:
    """Build a minimal NXDOMAIN DNS reply for a query."""

    if len(query) < 12:
        return b""
    transaction_id = query[:2]
    flags = b"\x81\x83"
    question_count = query[4:6]
    empty_counts = b"\x00\x00\x00\x00\x00\x00"
    return transaction_id + flags + question_count + empty_counts + query[12:]
