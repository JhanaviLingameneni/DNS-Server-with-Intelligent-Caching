
import socket

import dns.flags
import dns.message
import dns.opcode
import dns.rdataclass
import dns.rdatatype

from resolver.dns_cache import DNSCache


class DNSResolver:
    def __init__(
        self,
        upstream_host="8.8.8.8",
        upstream_port=53,
        timeout=2.0,
    ):
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.timeout = timeout
        self.cache = DNSCache()

    def resolve(self, query: bytes) -> bytes:
        """Resolve a DNS query using the cache or upstream DNS server."""

        # Parse and validate the incoming query.
        try:
            request = dns.message.from_wire(query)
        except Exception as exc:
            raise ValueError("Invalid DNS query") from exc

        if request.flags & dns.flags.QR:
            raise ValueError("Expected a DNS query, received a response")

        if request.opcode() != dns.opcode.QUERY:
            raise ValueError("Unsupported DNS opcode")

        if len(request.question) != 1:
            raise ValueError("Exactly one DNS question is required")

        question = request.question[0]

        if question.rdclass != dns.rdataclass.IN:
            raise ValueError("Only IN class queries are supported")

        if question.rdtype not in (
            dns.rdatatype.A,
            dns.rdatatype.AAAA,
        ):
            raise ValueError("Only A and AAAA queries are supported")

        # Build a unique cache key for this DNS question.
        key = (
            question.name.canonicalize().to_text(),
            question.rdtype,
            question.rdclass,
        )

        # Check the cache first.
        cached_response = self.cache.get(key, request.id)

        if cached_response is not None:
            return cached_response

        # Forward the query to the upstream DNS server.
        try:
            with socket.socket(
                socket.AF_INET,
                socket.SOCK_DGRAM,
            ) as sock:
                sock.settimeout(self.timeout)
                sock.sendto(
                    query,
                    (self.upstream_host, self.upstream_port),
                )

                response, _ = sock.recvfrom(4096)

        except socket.timeout as exc:
            raise TimeoutError("Upstream DNS server timed out") from exc

        except OSError as exc:
            raise ConnectionError(
                f"Could not contact upstream DNS server: {exc}"
            ) from exc

        # Parse and validate the upstream response.
        try:
            answer = dns.message.from_wire(response)
        except Exception as exc:
            raise ValueError("Invalid response from upstream DNS server") from exc

        if not answer.flags & dns.flags.QR:
            raise ValueError("Upstream packet is not a DNS response")

        if answer.id != request.id:
            raise ValueError("Upstream transaction ID mismatch")

        if answer.question != request.question:
            raise ValueError("Upstream question does not match the query")

        if answer.opcode() != dns.opcode.QUERY:
            raise ValueError("Unexpected upstream DNS opcode")

        if answer.flags & dns.flags.TC:
            raise ValueError("Upstream response was truncated")

        # Store eligible responses in the cache.
        self.cache.put(key, response)

        return response

    def stats(self):
        """Return cache statistics."""
        return self.cache.stats()
