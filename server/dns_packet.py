"""DNS packet validation and error-response helpers (Member 1).

The server never builds real answers itself; it only checks incoming
queries and builds error replies. Real answers come from
DNSResolver.resolve(query: bytes) -> bytes (Member 2).
"""
import struct

import dns.flags
import dns.message
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype

HEADER_LEN = 12
SUPPORTED_TYPES = {dns.rdatatype.A, dns.rdatatype.AAAA}


class ValidationResult:
    """Outcome of validating a query.

    ok=True  -> forward the raw query to the resolver.
    ok=False -> send `error_response` back (or drop if it is None).
    """

    def __init__(self, ok, error_response=None, reason=""):
        self.ok = ok
        self.error_response = error_response
        self.reason = reason


def build_header_error(data: bytes, rcode: int) -> bytes | None:
    """Build a bare error reply from just the 12-byte header.

    Used when the packet is too broken for dnspython to parse.
    Returns None if there is not even a full header (packet is dropped).
    """
    if len(data) < HEADER_LEN:
        return None
    txid, flags = struct.unpack("!HH", data[:4])
    opcode_bits = flags & 0x7800      # keep the client's opcode
    rd_bit = flags & 0x0100           # echo Recursion Desired
    new_flags = 0x8000 | opcode_bits | rd_bit | 0x0080 | (rcode & 0x000F)  # QR=1, RA=1
    return struct.pack("!HHHHHH", txid, new_flags, 0, 0, 0, 0)


def build_error_response(query: dns.message.Message, rcode: int) -> bytes:
    """Error reply that keeps the transaction ID and question section."""
    resp = dns.message.make_response(query)
    resp.flags |= dns.flags.RA
    resp.set_rcode(rcode)
    return resp.to_wire()


def build_servfail(data: bytes) -> bytes | None:
    """SERVFAIL for when the resolver raises or times out."""
    try:
        return build_error_response(dns.message.from_wire(data), dns.rcode.SERVFAIL)
    except Exception:
        return build_header_error(data, dns.rcode.SERVFAIL)


def validate_query(data: bytes) -> ValidationResult:
    """Check that `data` is a standard DNS query we support."""
    if len(data) < HEADER_LEN:
        return ValidationResult(False, None, "shorter than DNS header; dropped")

    try:
        query = dns.message.from_wire(data)
    except Exception as exc:
        return ValidationResult(False, build_header_error(data, dns.rcode.FORMERR),
                                f"unparseable: {exc.__class__.__name__}")

    if query.flags & dns.flags.QR:
        # A response sent to us - never reply to responses (avoids loops).
        return ValidationResult(False, None, "QR bit set (packet is a response); dropped")

    if query.opcode() != dns.opcode.QUERY:
        return ValidationResult(False, build_error_response(query, dns.rcode.NOTIMP),
                                "opcode not QUERY")

    if len(query.question) != 1:
        return ValidationResult(False, build_error_response(query, dns.rcode.FORMERR),
                                f"expected 1 question, got {len(query.question)}")

    q = query.question[0]
    if q.rdclass != dns.rdataclass.IN:
        return ValidationResult(False, build_error_response(query, dns.rcode.NOTIMP),
                                "class not IN")

    if q.rdtype not in SUPPORTED_TYPES:
        return ValidationResult(False, build_error_response(query, dns.rcode.NOTIMP),
                                f"unsupported type {dns.rdatatype.to_text(q.rdtype)}")

    return ValidationResult(True)


def responses_match(query: bytes, response: bytes) -> bool:
    """Sanity check: resolver reply must carry the same transaction ID."""
    return len(response) >= 2 and query[:2] == response[:2]
