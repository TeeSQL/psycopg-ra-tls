"""Leader-discovery entrypoint: DNS-TXT manifest → postgres DSN → RA-TLS connect.

Wraps the existing ``connect``/``connect_async`` flow. The SDK user passes a
cluster-facing domain (e.g. ``monitor.teesql.com``) plus the manifest-signer
pubkey baked into the application; we resolve ``_teesql-leader.<domain>``,
verify the signature, rewrite the DSN to point at the manifest's leader_url,
and delegate to the regular RA-TLS connect which verifies the TDX quote.

Failure modes handled per spec §7.3:
  * TXT fetch fails / stale / wrong signer → surface as ``ManifestError``.
  * Connection to the leader URL fails → caller can refresh + retry once.
  * Quote verification fails → hard failure; do not retry.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse, urlunparse

import psycopg
import psycopg.rows

from ra_tls_verify import RaTlsVerifier, VerifyOptions

from .connect import connect, connect_async
from .discovery import build_record_name, postgres_host_from_leader_url, query_manifest_txt
from .manifest import Manifest, parse_and_verify

logger = logging.getLogger(__name__)


def resolve_leader(
    cluster_domain: str,
    manifest_signer: bytes,
    *,
    resolver_ips: list[str] | None = None,
    timeout: float = 5.0,
) -> Manifest:
    """Resolve ``_teesql-leader.<cluster_domain>`` TXT and verify the manifest.

    Returns the parsed manifest on success; raises ``ManifestError`` otherwise.
    """
    record = build_record_name(cluster_domain)
    txt = query_manifest_txt(record, resolver_ips=resolver_ips, timeout=timeout)
    return parse_and_verify(txt, manifest_signer)


def _rewrite_dsn(dsn: str, host: str, port: int) -> str:
    """Replace the host:port in ``dsn`` with ``host:port`` while preserving
    user, password, database, and query params."""
    if not (dsn.startswith("postgresql://") or dsn.startswith("postgres://")):
        raise ValueError(
            "connect_via_manifest requires a URI-form DSN "
            "(postgresql://user:pw@.../db)"
        )
    parsed = urlparse(dsn)
    userinfo, _, _ = parsed.netloc.partition("@")
    if userinfo:
        new_netloc = f"{userinfo}@{host}:{port}"
    else:
        new_netloc = f"{host}:{port}"
    return urlunparse(parsed._replace(netloc=new_netloc))


def connect_via_manifest(
    cluster_domain: str,
    dsn_template: str,
    manifest_signer: bytes,
    verifier: RaTlsVerifier,
    options: VerifyOptions | None = None,
    *,
    allow_simulator: bool = False,
    resolver_ips: list[str] | None = None,
    row_factory: Any = None,
    **kwargs: Any,
) -> psycopg.Connection[Any]:
    """Discover the current leader via DNS TXT and open a connection.

    Args:
        cluster_domain: DNS label owned by the cluster operator, e.g.
            ``monitor.teesql.com``. Must exist as
            ``_teesql-leader.<cluster_domain>`` TXT.
        dsn_template: DSN whose host:port will be overwritten with the
            leader's URL. Only user, password, database, and query
            params are preserved.
        manifest_signer: 20-byte ethereum-style address of the
            manifest-signer key, baked into the SDK at build time.
        verifier, options, allow_simulator, row_factory, **kwargs: passed
            through to :func:`connect`.
    """
    manifest = resolve_leader(
        cluster_domain, manifest_signer, resolver_ips=resolver_ips
    )
    logger.info(
        "manifest resolved: cluster=%s epoch=%d leader_url=%s",
        manifest.cluster,
        manifest.epoch,
        manifest.leader_url,
    )
    host, port = postgres_host_from_leader_url(manifest.leader_url)
    dsn = _rewrite_dsn(dsn_template, host, port)
    return connect(
        dsn,
        verifier=verifier,
        options=options,
        allow_simulator=allow_simulator,
        row_factory=row_factory,
        **kwargs,
    )


async def connect_via_manifest_async(
    cluster_domain: str,
    dsn_template: str,
    manifest_signer: bytes,
    verifier: RaTlsVerifier,
    options: VerifyOptions | None = None,
    *,
    allow_simulator: bool = False,
    resolver_ips: list[str] | None = None,
    row_factory: Any = None,
    **kwargs: Any,
) -> psycopg.AsyncConnection[Any]:
    """Async variant of :func:`connect_via_manifest`."""
    manifest = resolve_leader(
        cluster_domain, manifest_signer, resolver_ips=resolver_ips
    )
    logger.info(
        "manifest resolved: cluster=%s epoch=%d leader_url=%s",
        manifest.cluster,
        manifest.epoch,
        manifest.leader_url,
    )
    host, port = postgres_host_from_leader_url(manifest.leader_url)
    dsn = _rewrite_dsn(dsn_template, host, port)
    return await connect_async(
        dsn,
        verifier=verifier,
        options=options,
        allow_simulator=allow_simulator,
        row_factory=row_factory,
        **kwargs,
    )
