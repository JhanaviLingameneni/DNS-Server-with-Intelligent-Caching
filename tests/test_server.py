"""Server tests using the mock resolver (Member 1). Run: pytest -v"""
import socket
import threading

import dns.message
import dns.rcode
import pytest

from server.dns_server import DNSServer
from server.mock_resolver import FAKE_A, MockResolver


@pytest.fixture
def server():
    srv = DNSServer(MockResolver(fail_on={"timeout.test."}), port=0)
    srv.start()
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.stop()


def send(srv, data: bytes, timeout=2.0):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(data, (srv.host, srv.port))
        return s.recvfrom(4096)[0]


def ask(srv, name, rdtype="A"):
    q = dns.message.make_query(name, rdtype)
    return q, dns.message.from_wire(send(srv, q.to_wire()))


def test_valid_a_query(server):
    q, r = ask(server, "example.com", "A")
    assert r.id == q.id
    assert r.rcode() == dns.rcode.NOERROR
    assert r.answer[0][0].address == FAKE_A


def test_valid_aaaa_query(server):
    q, r = ask(server, "example.com", "AAAA")
    assert r.id == q.id and r.answer


def test_nxdomain_passed_through(server):
    _, r = ask(server, "nonexistent.example.com")
    assert r.rcode() == dns.rcode.NXDOMAIN


def test_unsupported_type_notimp(server):
    q, r = ask(server, "example.com", "MX")
    assert r.id == q.id and r.rcode() == dns.rcode.NOTIMP
    assert server.resolver.calls == 0   # never forwarded


def test_malformed_packet_formerr(server):
    garbage = b"\x12\x34" + b"\x01\x00" + b"\x00\x01" + b"\x00" * 6 + b"\xff\xff\xff"
    r = send(server, garbage)
    assert r[:2] == b"\x12\x34"                 # same transaction ID
    assert (r[3] & 0x0F) == dns.rcode.FORMERR


def test_tiny_packet_dropped(server):
    with pytest.raises(socket.timeout):
        send(server, b"\x00\x01", timeout=0.5)


def test_resolver_failure_servfail(server):
    _, r = ask(server, "timeout.test")
    assert r.rcode() == dns.rcode.SERVFAIL


def test_multiple_clients(server):
    names = [f"host{i}.example.com" for i in range(20)]
    results = {}

    def worker(n):
        q, r = ask(server, n)
        results[n] = (q.id == r.id, r.question[0].name.to_text())

    threads = [threading.Thread(target=worker, args=(n,)) for n in names]
    [t.start() for t in threads]
    [t.join() for t in threads]
    for n in names:
        assert results[n] == (True, n + ".")   # each client got its own answer
