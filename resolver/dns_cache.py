
import threading
import time

import dns.message
import dns.rcode


class DNSCache:
    def __init__(self):
        self._cache = {}
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0

    def get(self, key, query_id):
        """Return a cached response with updated TTLs and transaction ID."""
        with self._lock:
            entry = self._cache.get(key)

            if entry is None:
                self._misses += 1
                return None

            response_bytes, stored_at, original_ttl = entry
            elapsed = time.monotonic() - stored_at

            if elapsed >= original_ttl:
                del self._cache[key]
                self._misses += 1
                return None

            elapsed_seconds = int(elapsed)

            response = dns.message.from_wire(response_bytes)

            # Update every resource record set's remaining TTL.
            for section in (
                response.answer,
                response.authority,
                response.additional,
            ):
                for rrset in section:
                    rrset.ttl = max(0, rrset.ttl - elapsed_seconds)

            # The cached response must use the current query's ID.
            response.id = query_id

            self._hits += 1
            return response.to_wire()

    def put(self, key, response_bytes):
        """Store an eligible successful DNS response."""
        try:
            response = dns.message.from_wire(response_bytes)

            # Do not cache errors, NXDOMAIN, or responses without answers.
            if response.rcode() != dns.rcode.NOERROR:
                return

            if not response.answer:
                return

            ttl_values = [rrset.ttl for rrset in response.answer]

            if not ttl_values:
                return

            original_ttl = min(ttl_values)

            # A zero-TTL response must not be cached.
            if original_ttl <= 0:
                return

            entry = (
                response_bytes,
                time.monotonic(),
                original_ttl,
            )

            with self._lock:
                self._cache[key] = entry

        except Exception:
            # Invalid or uncacheable responses are simply not stored.
            return

    def stats(self):
        """Return cache statistics."""
        with self._lock:
            return {
                "cache_hits": self._hits,
                "cache_misses": self._misses,
                "cache_entries": len(self._cache),
            }

    def clear(self):
        """Clear all cached entries and reset counters."""
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0
