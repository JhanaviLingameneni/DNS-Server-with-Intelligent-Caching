"""UDP DNS server (Member 1).

Receives DNS queries, validates them, passes valid ones to
DNSResolver.resolve(query: bytes) -> bytes, and sends the reply back
to the client that asked.

Run:
    python -m server.dns_server --mock                 # with mock resolver
    python -m server.dns_server --port 8053            # with real resolver
"""
import argparse
import logging
import socket
import threading
from concurrent.futures import ThreadPoolExecutor

from server.dns_packet import build_servfail, responses_match, validate_query

log = logging.getLogger("dns_server")
MAX_UDP = 512 * 8  # accept up to 4096 bytes (EDNS-sized queries)


class DNSServer:
    def __init__(self, resolver, host="127.0.0.1", port=8053, workers=8):
        self.resolver = resolver
        self.host = host
        self.port = port
        self.sock = None
        self.pool = ThreadPoolExecutor(max_workers=workers)
        self._running = threading.Event()
        self.stats = {"received": 0, "answered": 0, "errors": 0, "dropped": 0}
        self._lock = threading.Lock()

    def _count(self, key):
        with self._lock:
            self.stats[key] += 1

    def start(self):
        """Bind the socket. Port 0 picks a free port (useful in tests)."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            # Windows: fail loudly if another program (e.g. mDNS on 5353) owns the port
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.settimeout(0.5)   # lets serve_forever notice stop()
        self.port = self.sock.getsockname()[1]
        self._running.set()
        log.info("Listening on %s:%d (UDP)", self.host, self.port)

    def serve_forever(self):
        while self._running.is_set():
            try:
                data, addr = self.sock.recvfrom(MAX_UDP)
            except socket.timeout:
                continue
            except OSError:
                break   # socket closed
            self._count("received")
            # Each request handled in a worker thread -> multiple clients at once.
            self.pool.submit(self.handle, data, addr)

    def handle(self, data: bytes, addr):
        try:
            reply = self.process(data, addr)
            if reply is None:
                self._count("dropped")
                return
            self.sock.sendto(reply, addr)
        except Exception:
            log.exception("Unexpected error handling packet from %s", addr)
            self._count("errors")

    def process(self, data: bytes, addr) -> bytes | None:
        """Turn one incoming packet into one reply (or None to drop)."""
        result = validate_query(data)
        if not result.ok:
            log.warning("Rejected packet from %s: %s", addr, result.reason)
            if result.error_response is not None:
                self._count("errors")
            return result.error_response

        try:
            response = self.resolver.resolve(data)
        except Exception as exc:
            log.error("Resolver failed for %s: %s", addr, exc)
            self._count("errors")
            return build_servfail(data)

        if not responses_match(data, response):
            log.error("Resolver returned mismatched transaction ID")
            self._count("errors")
            return build_servfail(data)

        self._count("answered")
        return response

    def stop(self):
        self._running.clear()
        if self.sock:
            self.sock.close()
        self.pool.shutdown(wait=False)


def load_resolver(use_mock: bool, upstream: str, timeout: float):
    if use_mock:
        from server.mock_resolver import MockResolver
        return MockResolver()
    # Real resolver from Member 2. Adjust the constructor once their API is final.
    from resolver.dns_forwarder import DNSResolver
    host, _, port = upstream.partition(":")
    return DNSResolver(upstream_host=host, upstream_port=int(port or 53), timeout=timeout)


def main():
    p = argparse.ArgumentParser(description="CSCI 651 caching DNS server")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8053)
    p.add_argument("--upstream", default="8.8.8.8:53")
    p.add_argument("--timeout", type=float, default=2.0)
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--mock", action="store_true", help="use the mock resolver")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    server = DNSServer(load_resolver(args.mock, args.upstream, args.timeout),
                       args.host, args.port, args.workers)
    server.start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down. Stats: %s", server.stats)
    finally:
        server.stop()


if __name__ == "__main__":
    main()
