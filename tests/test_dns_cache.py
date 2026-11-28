
import time

import dns.message
import dns.rrset

from resolver.dns_cache import DNSCache


def make_response(domain="example.com.", ttl=30):
    query = dns.message.make_query(domain, "A")
    response = dns.message.make_response(query)

    response.answer.append(
        dns.rrset.from_text(
            domain, ttl, "IN", "A", "93.184.216.34"
        )
    )

    return response.to_wire()


def test_cache_hit_and_transaction_id():
    cache = DNSCache()
    key = ("example.com.", 1, 1)

    cache.put(key, make_response())

    result = cache.get(key, 5678)

    assert result is not None

    response = dns.message.from_wire(result)
    assert response.id == 5678


def test_cache_miss():
    cache = DNSCache()

    result = cache.get(("example.com.", 1, 1), 1234)

    assert result is None
    assert cache.stats()["cache_misses"] == 1


def test_ttl_decreases():
    cache = DNSCache()
    key = ("example.com.", 1, 1)

    cache.put(key, make_response(ttl=30))

    time.sleep(2)

    result = cache.get(key, 1234)
    response = dns.message.from_wire(result)

    assert response.answer[0].ttl < 30


def test_expired_entry():
    cache = DNSCache()
    key = ("example.com.", 1, 1)

    cache.put(key, make_response(ttl=1))

    time.sleep(1.2)

    assert cache.get(key, 1234) is None


def test_nxdomain_not_cached():
    cache = DNSCache()

    query = dns.message.make_query("missing.example.com", "A")
    response = dns.message.make_response(query)
    response.set_rcode(dns.rcode.NXDOMAIN)

    cache.put(("missing.example.com.", 1, 1), response.to_wire())

    assert cache.get(("missing.example.com.", 1, 1), 1234) is None
