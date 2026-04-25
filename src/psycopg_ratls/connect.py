"""RA-TLS verified psycopg3 connections to dstack TEE databases.

psycopg 0.8+ drives its own TLS handshake starting with the postgres
``SSLRequest`` 8-byte preamble, which the dstack gateway's TLS-passthrough
SNI router can't parse. See ``forwarder.py`` for the full rationale.

The mitigation: this module starts an in-process localhost
:class:`~psycopg_ratls.forwarder.RaTlsForwarder`, which terminates mutual
RA-TLS against the cluster and bridges bytes. psycopg then connects to the
forwarder with ``sslmode=disable``.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse, urlunparse

import psycopg
import psycopg.rows

from dstack_sdk import DstackClient
from ra_tls_verify import RaTlsVerifier, VerifyOptions

from . import forwarder as _forwarder
from .forwarder import RaTlsForwarder

# Placeholder password sent to the proxy when the DSN contains no password.
# The sidecar proxy discards whatever password the client sends and
# substitutes the KMS-derived password before forwarding to Postgres, so
# the actual value here never leaves the client.
_RATLS_PLACEHOLDER_PASSWORD = "ratls"

# Timeout passed to DstackClient when fetching a client cert. Default
# 3s is too tight — on a cold CVM the first cert request can take
# several seconds to walk the guest-agent → KMS roundtrip.
_DSTACK_CERT_TIMEOUT_SECS = 60

logger = logging.getLogger(__name__)


def _fetch_client_cert() -> tuple[str, str]:
    """Fetch a short-lived, TDX-attested client cert from the dstack guest agent.

    Returns ``(chain_pem, key_pem)`` — the chain concatenated as a single
    PEM string, and the private key PEM. Both are mandatory for the
    mutual-RA-TLS handshake against the teesql sidecar.
    """
    client = DstackClient(timeout=_DSTACK_CERT_TIMEOUT_SECS)
    resp = client.get_tls_key(
        usage_ra_tls=True,
        usage_server_auth=True,
        usage_client_auth=True,
    )
    chain_pem = "\n".join(resp.certificate_chain)
    if not chain_pem.endswith("\n"):
        chain_pem += "\n"
    return chain_pem, resp.key


def _parse_target(dsn: str) -> tuple[str, int, str]:
    """Extract ``(host, port, rest_of_dsn)`` from a URL-style DSN.

    Returns the host, port, and the DSN rewritten to a localhost listener
    placeholder — the caller substitutes in the forwarder's bound
    ``(host, port)`` before passing to psycopg.
    """
    if not (dsn.startswith("postgresql://") or dsn.startswith("postgres://")):
        raise ValueError(
            "psycopg-ra-tls requires a URI-form DSN (postgresql://user:pw@host:port/db)"
        )
    parsed = urlparse(dsn)
    host = parsed.hostname
    port = parsed.port or 5432
    if not host:
        raise ValueError("DSN has no host")
    return host, port, dsn


def _inject_placeholder_password(dsn: str) -> str:
    """Return a DSN guaranteed to have a password field.

    The sidecar's wire-protocol auth-injection replaces whatever password
    the client sent with the KMS-derived credential, so we only need the
    DSN to contain *something* for psycopg's URL parser.
    """
    if not (dsn.startswith("postgresql://") or dsn.startswith("postgres://")):
        return dsn
    parsed = urlparse(dsn)
    if parsed.password is not None:
        return dsn
    userinfo, _, hostinfo = parsed.netloc.partition("@")
    if not hostinfo:
        hostinfo = userinfo
        userinfo = ""
    if userinfo:
        new_userinfo = f"{userinfo}:{_RATLS_PLACEHOLDER_PASSWORD}"
    else:
        new_userinfo = f":{_RATLS_PLACEHOLDER_PASSWORD}"
    new_netloc = f"{new_userinfo}@{hostinfo}"
    return urlunparse(parsed._replace(netloc=new_netloc))


def _rewrite_to_forwarder(dsn: str, local_host: str, local_port: int) -> str:
    """Rewrite a URL DSN's host/port to the forwarder's local address and
    force ``sslmode=disable``.

    The forwarder terminates TLS against the cluster; by the time the
    postgres wire protocol flows, we're talking plain TCP across
    loopback. ``sslmode=disable`` avoids psycopg attempting its own TLS
    upgrade on top.
    """
    parsed = urlparse(dsn)
    userinfo, _, _ = parsed.netloc.partition("@")
    if not userinfo:
        # No userinfo → impossible for teesql sidecar (needs teesql_read/
        # teesql_readwrite), but tolerate for generic dstack postgres.
        userinfo = f":{_RATLS_PLACEHOLDER_PASSWORD}"
    elif ":" not in userinfo:
        # username but no password — add placeholder.
        userinfo = f"{userinfo}:{_RATLS_PLACEHOLDER_PASSWORD}"
    new_netloc = f"{userinfo}@{local_host}:{local_port}"

    # Merge query: force sslmode=disable (overrides any sslmode in the
    # caller's DSN).
    query = parsed.query
    params = [q for q in query.split("&") if q and not q.startswith("sslmode=")]
    params.append("sslmode=disable")
    new_query = "&".join(params)

    return urlunparse(parsed._replace(netloc=new_netloc, query=new_query))


def _start_forwarder(
    target_host: str,
    target_port: int,
    verifier: RaTlsVerifier,
    options: VerifyOptions | None,
    allow_simulator: bool,
) -> RaTlsForwarder:
    """Create + start an RA-TLS forwarder, keep a module-level reference."""
    chain_pem, key_pem = _fetch_client_cert()
    fwd = RaTlsForwarder(
        target_host=target_host,
        target_port=target_port,
        client_cert_chain_pem=chain_pem,
        client_key_pem=key_pem,
        verifier=verifier,
        options=options,
        allow_simulator=allow_simulator,
    )
    fwd.start()
    _forwarder.register(fwd)
    return fwd


def connect(
    dsn: str,
    verifier: RaTlsVerifier,
    options: VerifyOptions | None = None,
    allow_simulator: bool = False,
    row_factory: Any = None,
    **kwargs: Any,
) -> psycopg.Connection[Any]:
    """Connect to a dstack TEE database with mutual RA-TLS verification.

    The call opens an in-process RA-TLS forwarder bound to
    ``127.0.0.1:<ephemeral>`` that terminates mutual RA-TLS against the
    cluster and bridges bytes; psycopg then connects to the forwarder
    with ``sslmode=disable``. The caller sees a standard
    :class:`psycopg.Connection` and never has to reason about the TLS
    plumbing.

    Args:
        dsn: URL-form postgres DSN. User/password/database are preserved;
            host/port are rewritten to the forwarder's local address.
        verifier: Attestation verifier applied to every upstream
            handshake (e.g. ``IntelApiVerifier`` or ``NoopVerifier``).
        options: Verification options (MRTD allowlist, debug mode).
        allow_simulator: Accept upstream certs without an attestation
            extension. Dev/test use only.
        row_factory: psycopg row factory (default: ``dict_row``).
        **kwargs: Passed through to :func:`psycopg.connect`.

    Raises:
        RuntimeError: If the RA-TLS handshake fails at the first
            forwarded connection (surfaces as a psycopg connection error).
    """
    if row_factory is None:
        row_factory = psycopg.rows.dict_row

    target_host, target_port, _ = _parse_target(dsn)
    fwd = _start_forwarder(target_host, target_port, verifier, options, allow_simulator)
    local_host, local_port = fwd.local_addr

    local_dsn = _rewrite_to_forwarder(dsn, local_host, local_port)
    return psycopg.connect(local_dsn, row_factory=row_factory, **kwargs)


async def connect_async(
    dsn: str,
    verifier: RaTlsVerifier,
    options: VerifyOptions | None = None,
    allow_simulator: bool = False,
    row_factory: Any = None,
    **kwargs: Any,
) -> psycopg.AsyncConnection[Any]:
    """Async variant of :func:`connect`. Same trust model + forwarder pattern."""
    if row_factory is None:
        row_factory = psycopg.rows.dict_row

    target_host, target_port, _ = _parse_target(dsn)
    fwd = _start_forwarder(target_host, target_port, verifier, options, allow_simulator)
    local_host, local_port = fwd.local_addr

    local_dsn = _rewrite_to_forwarder(dsn, local_host, local_port)
    return await psycopg.AsyncConnection.connect(
        local_dsn, row_factory=row_factory, **kwargs
    )
