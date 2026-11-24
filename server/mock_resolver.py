"""Mock resolver so the server can be tested before Member 2's code exists.

Same interface as the real one: resolve(query: bytes) -> bytes.
"""
import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset

FAKE_A = "93.184.216.34"
FAKE_AAAA = "2606:2800:220:1:248:1893:25c8:1946"


class MockResolver:
    def __init__(self, fail_on=None):
        self.calls = 0
        self.fail_on = set(fail_on or [])   # domain names that raise

    def resolve(self, query: bytes) -> bytes:
        self.calls += 1
        msg = dns.message.from_wire(query)
        q = msg.question[0]
        name = q.name.to_text()
        if name in self.fail_on:
            raise TimeoutError("mock upstream timeout")

        resp = dns.message.make_response(msg)   # keeps transaction ID
        if name.startswith("nonexistent"):
            resp.set_rcode(dns.rcode.NXDOMAIN)
            return resp.to_wire()
        value = FAKE_A if q.rdtype == dns.rdatatype.A else FAKE_AAAA
        resp.answer.append(dns.rrset.from_text(q.name, 300, "IN",
                                               dns.rdatatype.to_text(q.rdtype), value))
        return resp.to_wire()
