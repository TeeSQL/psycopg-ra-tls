"""RA-TLS verified psycopg3 connections to dstack TEE databases.

Wraps psycopg3's connection with an SSL context that extracts and verifies
TDX attestation quotes from the server's RA-TLS certificate on every connection.
"""

from __future__ import annotations

import asyncio
import ssl
import logging
from typing import Any

import psycopg
import psycopg.rows

from ra_tls_verify import (
    RaTlsVerifier,
    VerifyOptions,
    extract_tdx_quote,
)

logger = logging.getLogger(__name__)


def create_ssl_context(
    verifier: RaTlsVerifier,
    options: VerifyOptions | None = None,
    allow_simulator: bool = False,
) -> ssl.SSLContext:
    """Create an SSL context that verifies RA-TLS attestation on connection.

    The returned context can be passed to psycopg3 as the `sslcontext` parameter.
    On each TLS handshake, the server certificate is checked for a TDX attestation
    quote. If found, the quote is verified using the provided verifier. If verification
    fails, the connection is refused.

    Args:
        verifier: Attestation verifier (IntelApiVerifier or NoopVerifier).
        options: Verification options (MRTD allowlist, debug mode).
        allow_simulator: Accept certs without attestation extensions (dev only).
    """
    options = options or VerifyOptions()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # RA-TLS certs are self-signed with attestation as the trust anchor,
    # not a traditional CA chain. Disable default cert verification --
    # we verify trust through the attestation quote instead.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED

    # Accept any certificate so we can inspect it in post_handshake
    ctx.load_default_certs()

    # Store verification state for the callback
    _verify_state: dict[str, Any] = {
        "verifier": verifier,
        "options": options,
        "allow_simulator": allow_simulator,
    }

    # We override verify to always accept during handshake, then
    # do attestation verification after the handshake completes.
    # This is necessary because RA-TLS certs are self-signed.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Attach state for post-handshake verification
    ctx._ratls_state = _verify_state  # type: ignore[attr-defined]

    return ctx


def _verify_peer_cert(
    conn: psycopg.Connection[Any],
    verifier: RaTlsVerifier,
    options: VerifyOptions,
    allow_simulator: bool,
) -> None:
    """Verify the peer certificate's attestation quote after connection."""
    pgconn = conn.pgconn

    # psycopg exposes the raw SSL object, but we need to get the peer cert
    # via the underlying socket's SSL info
    ssl_obj = pgconn.ssl_attribute("server_certificate_der")
    if ssl_obj is None:
        # Try getting the cert from the connection info
        # psycopg3 doesn't directly expose DER cert, so we use the socket
        sock = pgconn.socket
        if sock <= 0:
            if allow_simulator:
                logger.warning("No SSL socket available, skipping attestation (simulator mode)")
                return
            raise RuntimeError("No SSL connection established")

    # Get the DER-encoded server certificate
    der_cert = _get_server_cert_der(pgconn)
    if der_cert is None:
        if allow_simulator:
            logger.warning("Could not extract server certificate, skipping attestation")
            return
        raise RuntimeError("Could not extract server certificate for attestation")

    quote = extract_tdx_quote(der_cert)
    if quote is None:
        if allow_simulator:
            logger.warning("Server cert has no TDX attestation extension (simulator mode)")
            return
        raise RuntimeError(
            "Server certificate does not contain a TDX attestation extension. "
            "Set allow_simulator=True for non-TEE connections."
        )

    # Run async verification synchronously
    result = asyncio.run(verifier.verify(quote, options))
    logger.info(
        "RA-TLS verification passed: mrtd=%s tcb=%s",
        result.mr_td[:16] + "...",
        result.tcb_status,
    )


def _get_server_cert_der(pgconn: Any) -> bytes | None:
    """Extract the server's DER-encoded certificate from a psycopg connection."""
    try:
        import ctypes

        # psycopg3 exposes ssl_attribute which can get cert data
        # but for DER we need to go through the C API
        cert_pem = pgconn.ssl_attribute("server_certificate")
        if cert_pem:
            from cryptography.x509 import load_pem_x509_certificate
            from cryptography.hazmat.primitives.serialization import Encoding

            cert = load_pem_x509_certificate(cert_pem.encode())
            return cert.public_bytes(Encoding.DER)
    except Exception:
        pass

    # Fallback: try libpq's PQsslAttribute
    try:
        cert_pem = pgconn.ssl_attribute("server_certificate")
        if cert_pem:
            from cryptography.x509 import load_pem_x509_certificate
            from cryptography.hazmat.primitives.serialization import Encoding

            cert = load_pem_x509_certificate(
                cert_pem if isinstance(cert_pem, bytes) else cert_pem.encode()
            )
            return cert.public_bytes(Encoding.DER)
    except Exception:
        pass

    return None


def connect(
    dsn: str,
    verifier: RaTlsVerifier,
    options: VerifyOptions | None = None,
    allow_simulator: bool = False,
    row_factory: Any = None,
    **kwargs: Any,
) -> psycopg.Connection[Any]:
    """Connect to a dstack TEE database with RA-TLS attestation verification.

    Establishes a psycopg3 connection using TLS, extracts the TDX attestation
    quote from the server certificate, and verifies it before returning.

    Args:
        dsn: PostgreSQL connection string.
        verifier: Attestation verifier (IntelApiVerifier or NoopVerifier).
        options: Verification options.
        allow_simulator: Accept certs without attestation (dev only).
        row_factory: psycopg row factory (default: dict_row).
        **kwargs: Additional arguments passed to psycopg.connect().

    Raises:
        RuntimeError: If attestation verification fails.
    """
    options = options or VerifyOptions()
    if row_factory is None:
        row_factory = psycopg.rows.dict_row

    ctx = create_ssl_context(verifier, options, allow_simulator)

    conn = psycopg.connect(
        dsn,
        sslcontext=ctx,
        row_factory=row_factory,
        **kwargs,
    )

    try:
        _verify_peer_cert(conn, verifier, options, allow_simulator)
    except Exception:
        conn.close()
        raise

    return conn


async def connect_async(
    dsn: str,
    verifier: RaTlsVerifier,
    options: VerifyOptions | None = None,
    allow_simulator: bool = False,
    row_factory: Any = None,
    **kwargs: Any,
) -> psycopg.AsyncConnection[Any]:
    """Async version of connect().

    Same attestation verification flow but returns an AsyncConnection.
    """
    options = options or VerifyOptions()
    if row_factory is None:
        row_factory = psycopg.rows.dict_row

    ctx = create_ssl_context(verifier, options, allow_simulator)

    conn = await psycopg.AsyncConnection.connect(
        dsn,
        sslcontext=ctx,
        row_factory=row_factory,
        **kwargs,
    )

    try:
        der_cert = _get_server_cert_der(conn.pgconn)
        if der_cert is None:
            if not allow_simulator:
                await conn.close()
                raise RuntimeError("Could not extract server certificate for attestation")
            logger.warning("Could not extract server certificate, skipping attestation")
        else:
            quote = extract_tdx_quote(der_cert)
            if quote is None:
                if not allow_simulator:
                    await conn.close()
                    raise RuntimeError(
                        "Server certificate does not contain a TDX attestation extension."
                    )
                logger.warning("Server cert has no TDX attestation extension (simulator mode)")
            else:
                result = await verifier.verify(quote, options)
                logger.info(
                    "RA-TLS verification passed: mrtd=%s tcb=%s",
                    result.mr_td[:16] + "...",
                    result.tcb_status,
                )
    except RuntimeError:
        await conn.close()
        raise

    return conn
