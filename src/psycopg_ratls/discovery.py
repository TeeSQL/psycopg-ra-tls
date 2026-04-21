"""DNS TXT lookup for the teesql cluster-leader manifest.

Goes around the system resolver cache so a leader change propagates in
``record_ttl_secs`` (30s by default) rather than whatever getaddrinfo
remembers. Uses ``dnspython`` with authoritative NS lookup disabled — we
trust Cloudflare's own resolver and let it handle TTLs.
"""

from __future__ import annotations

from urllib.parse import urlparse

import dns.resolver


def query_manifest_txt(
    record_name: str,
    *,
    resolver_ips: list[str] | None = None,
    timeout: float = 5.0,
) -> str:
    """Resolve TXT for ``record_name``, reassembling multi-chunk strings.

    Cloudflare splits >255-byte TXT bodies into multiple 255-byte chunks; a
    standard TXT RR returns them as a list that the receiver concatenates.
    ``dnspython`` gives us the raw chunks — we join them.

    If ``resolver_ips`` is given, those are queried directly (DNS recursion
    bypassing /etc/resolv.conf). Default resolver is used otherwise.
    """
    resolver = dns.resolver.Resolver(configure=resolver_ips is None)
    if resolver_ips is not None:
        resolver.nameservers = resolver_ips
    resolver.lifetime = timeout

    answer = resolver.resolve(record_name, rdtype="TXT")
    # A TXT RRset may contain multiple records; we only expect one. If there's
    # more than one, pick the first — they should be identical under the
    # active-active controller design.
    for rdata in answer:
        # rdata.strings is a tuple[bytes] of chunks.
        joined = b"".join(rdata.strings).decode("utf-8")
        return joined
    raise RuntimeError(f"no TXT records at {record_name}")


def build_record_name(cluster_domain: str) -> str:
    """`monitor.teesql.com` → `_teesql-leader.monitor.teesql.com`."""
    label = "_teesql-leader"
    if cluster_domain.startswith(label + "."):
        return cluster_domain
    return f"{label}.{cluster_domain}"


def postgres_host_from_leader_url(leader_url: str) -> tuple[str, int]:
    """Extract (host, port) for a postgres DSN from the manifest's leader_url.

    Phala gateway URLs look like
    ``https://<instance>-5433.<kms-node>.phala.network`` and TLS-wrap the
    postgres wire protocol on 443. Self-hosted members may publish arbitrary
    URLs; we honor whatever port the URL specifies (443 by default for https,
    80 for http) and let the caller's RA-TLS handshake reject hosts whose
    cert SAN doesn't match.
    """
    parsed = urlparse(leader_url)
    if parsed.hostname is None:
        raise ValueError(f"leader_url has no hostname: {leader_url}")
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    return parsed.hostname, port
