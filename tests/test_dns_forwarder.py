
import socket

import dns.message
import dns.rrset

from resolver.dns_forwarder import DNSResolver


class MockUpstream:
    def __init__(self):
        self.calls = 0

    def sendto(self, data, address):
        self.calls += 1
        query = dns.message.from_wire(data)

        response = dns.message.make_response(query)
        question = query.question[0]

        if question.rdtype == dns.rdatatype.A:
            response.answer.append(
                dns.rrset.from_text(
                    question.name.to_text(),
                    30,
                    "IN",
                    "A",
                    "93.184.216.34",
                )
            )

        elif question.rdtype == dns.rdatatype.AAAA:
            response.answer.append(
                dns.rrset.from_text(
                    question.name.to_text(),
                    30,
                    "IN",
                    "AAAA",
                    "2606:2800:220:1:248:1893:25c8:1946",
                )
            )

        self.response = response.to_wire()

    def recvfrom(self, size):
        return self.response, ("8.8.8.8", 53)


def test_forwarder_uses_cache(monkeypatch):
    mock = MockUpstream()

    def mock_socket(*args, **kwargs):
        return MockSocket(mock)

    class MockSocket:
        def __init__(self, upstream):
            self.upstream = upstream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def settimeout(self, timeout):
            pass

        def sendto(self, data, address):
            self.upstream.sendto(data, address)

        def recvfrom(self, size):
            return self.upstream.recvfrom(size)

    monkeypatch.setattr(socket, "socket", mock_socket)

    resolver = DNSResolver()

    query1 = dns.message.make_query("example.com", "A")
    query1.id = 1234

    result1 = resolver.resolve(query1.to_wire())

    query2 = dns.message.make_query("example.com", "A")
    query2.id = 5678

    result2 = resolver.resolve(query2.to_wire())

    response2 = dns.message.from_wire(result2)

    assert mock.calls == 1
    assert response2.id == 5678
    assert len(response2.answer) == 1


def test_a_and_aaaa_use_separate_cache_entries(monkeypatch):
    mock = MockUpstream()

    class MockSocket:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def settimeout(self, timeout):
            pass

        def sendto(self, data, address):
            mock.sendto(data, address)

        def recvfrom(self, size):
            return mock.recvfrom(size)

    monkeypatch.setattr(
        socket,
        "socket",
        lambda *args, **kwargs: MockSocket(),
    )

    resolver = DNSResolver()

    a_query = dns.message.make_query("example.com", "A")
    aaaa_query = dns.message.make_query("example.com", "AAAA")

    resolver.resolve(a_query.to_wire())
    resolver.resolve(aaaa_query.to_wire())

    assert mock.calls == 2


def test_unsupported_query_type():
    resolver = DNSResolver()

    query = dns.message.make_query("example.com", "MX")

    try:
        resolver.resolve(query.to_wire())
        assert False, "Expected ValueError"
    except ValueError:
        pass


def test_cache_statistics():
    resolver = DNSResolver()

    stats = resolver.stats()

    assert stats["cache_hits"] == 0
    assert stats["cache_misses"] == 0
    assert stats["cache_entries"] == 0
