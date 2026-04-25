"""Local TCP forwarder that terminates RA-TLS on behalf of the postgres driver.

Why this exists
---------------

The dstack gateway in TLS-passthrough mode routes by parsing the TLS
ClientHello's SNI to pick a target CVM, *before* forwarding raw bytes on.
Standard postgres clients (libpq, psycopg, sqlx, prisma) start every
``sslmode=require`` connection with the postgres-specific ``SSLRequest``
8-byte plaintext preamble and wait for a single-byte reply before sending
the TLS ClientHello. The gateway sees the SSLRequest as the first bytes,
fails SNI extraction (first byte ``0x00`` is not the TLS handshake record
type ``0x16``), and closes the connection.

We can't trust the customer's CVM absent the RA-TLS handshake itself, so
we can't give customers a raw sidecar endpoint that bypasses the gateway.
That rules out "psycopg does its own TLS handshake" as the data-plane path.

The fix moves TLS out of psycopg. This module runs a localhost
``asyncio`` TCP server inside the client process; on every accept it
opens a *raw* TLS connection (no ``SSLRequest`` preamble) to the cluster,
presents the dstack-issued RA-TLS client certificate, verifies the
server's TDX quote via the caller's verifier, and then bridges bytes
bidirectionally between the accepted local stream and the TLS-wrapped
upstream stream.

From psycopg's perspective it's talking to a plain-TCP local postgres
server with ``sslmode=disable``. From the sidecar's perspective it's
getting a raw-TLS mutual-RA-TLS handshake with a valid client cert. The
gateway sees a well-formed TLS ClientHello in the first bytes and routes
happily.

Trust model
-----------

The local hop (psycopg ↔ forwarder ↔ TLS tunnel) lives inside the
client process — both ends are the same TEE CVM. The plaintext segment
never crosses a process boundary or an untrusted network. The actual
mutual-RA-TLS handshake happens on the upstream leg, exactly as the
trust model documents.

Lifecycle
---------

``RaTlsForwarder`` spawns a daemon thread running its own ``asyncio``
event loop. The thread dies with the process. For the common
"one-connection-per-call" ``connect()`` flow we keep a module-level
list of forwarders so Python's GC doesn't collect them while they're
still forwarding bytes.
"""

from __future__ import annotations

import asyncio
import logging
import os
import ssl
import tempfile
import threading
from typing import Any

from ra_tls_verify import RaTlsVerifier, VerifyOptions, extract_tdx_quote

logger = logging.getLogger(__name__)

# Keep a reference to every started forwarder so the daemon thread + its
# event loop + its listener socket don't get GC'd while the postgres
# driver still has open connections to the listener.
_FORWARDERS: list["RaTlsForwarder"] = []


class RaTlsForwarder:
    """Background localhost forwarder that terminates mutual RA-TLS."""

    def __init__(
        self,
        target_host: str,
        target_port: int,
        client_cert_chain_pem: str,
        client_key_pem: str,
        verifier: RaTlsVerifier,
        options: VerifyOptions | None = None,
        allow_simulator: bool = False,
    ) -> None:
        self.target_host = target_host
        self.target_port = target_port
        self.client_cert_chain_pem = client_cert_chain_pem
        self.client_key_pem = client_key_pem
        self.verifier = verifier
        self.options = options or VerifyOptions()
        self.allow_simulator = allow_simulator

        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._server: asyncio.AbstractServer | None = None
        self._ready = threading.Event()
        self._local_addr: tuple[str, int] | None = None
        self._cert_path: str | None = None
        self._key_path: str | None = None

    @property
    def local_addr(self) -> tuple[str, int]:
        """``(host, port)`` of the forwarder's localhost listener.

        Only valid after :py:meth:`start` has returned.
        """
        if self._local_addr is None:
            raise RuntimeError("RaTlsForwarder: start() has not been called")
        return self._local_addr

    def start(self) -> None:
        """Start the forwarder. Blocks until the listener is bound."""
        # ssl.SSLContext.load_cert_chain wants file paths; write the dstack-
        # issued PEMs to tempfiles (process-scoped, mode 600). We keep them
        # alive for the lifetime of the forwarder — they're reloaded on
        # every outgoing TLS handshake so a cert rotation would need a new
        # forwarder, same as sqlx-ra-tls.
        self._cert_path = _write_mode_600_tempfile(self.client_cert_chain_pem, ".crt")
        self._key_path = _write_mode_600_tempfile(self.client_key_pem, ".key")

        self._thread = threading.Thread(
            target=self._run,
            name=f"ra-tls-forwarder-{self.target_host}:{self.target_port}",
            daemon=True,
        )
        self._thread.start()
        self._ready.wait()

    def _run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._bind())
            self._loop.run_forever()
        finally:
            self._loop.close()

    async def _bind(self) -> None:
        self._server = await asyncio.start_server(
            self._handle, host="127.0.0.1", port=0
        )
        sock = self._server.sockets[0].getsockname()
        # sock is (host, port, ...) for IPv4, or (host, port, flowinfo, scopeid) for IPv6.
        self._local_addr = (sock[0], sock[1])
        self._ready.set()

    async def _handle(
        self,
        local_reader: asyncio.StreamReader,
        local_writer: asyncio.StreamWriter,
    ) -> None:
        try:
            await self._handle_inner(local_reader, local_writer)
        except Exception as e:
            # Normal disconnects (pool connection close) surface here as
            # ConnectionResetError / BrokenPipeError; log at debug so we
            # don't spam on every graceful pool cycle.
            if isinstance(e, (ConnectionResetError, BrokenPipeError)):
                logger.debug("psycopg-ra-tls forwarder: %s", e)
            else:
                logger.warning("psycopg-ra-tls forwarder: connection failed: %s", e)
        finally:
            try:
                local_writer.close()
                await local_writer.wait_closed()
            except Exception:
                pass

    async def _handle_inner(
        self,
        local_reader: asyncio.StreamReader,
        local_writer: asyncio.StreamWriter,
    ) -> None:
        # Per-connection SSLContext so a rotated dstack cert could take
        # effect on a fresh forwarder without restarting the process.
        # Within a single forwarder's lifetime we load the same cert each
        # time — cheap, and simpler than cache invalidation.
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_cert_chain(certfile=self._cert_path, keyfile=self._key_path)
        # RA-TLS: server cert is self-signed with trust in the embedded
        # TDX quote, not PKI. Skip hostname + chain verification here;
        # we run verifier.verify() on the extracted quote below.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        upstream_reader, upstream_writer = await asyncio.open_connection(
            self.target_host,
            self.target_port,
            ssl=ctx,
            server_hostname=self.target_host,
        )

        ssl_obj = upstream_writer.get_extra_info("ssl_object")
        if ssl_obj is None:
            raise RuntimeError("upstream connection is not TLS")
        der_cert = ssl_obj.getpeercert(binary_form=True)
        if der_cert is None:
            raise RuntimeError("upstream presented no leaf certificate")

        quote = extract_tdx_quote(der_cert)
        if quote is None:
            if not self.allow_simulator:
                raise RuntimeError(
                    "upstream cert has no TDX attestation extension; "
                    "set allow_simulator=True for non-TEE targets"
                )
            logger.warning("upstream cert has no TDX quote (simulator mode)")
        else:
            result = await self.verifier.verify(quote, self.options)
            logger.debug(
                "RA-TLS upstream verified: mrtd=%s... tcb=%s",
                result.mr_td[:16],
                result.tcb_status,
            )

        await _bridge(local_reader, local_writer, upstream_reader, upstream_writer)


def _write_mode_600_tempfile(content: str, suffix: str) -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    try:
        os.write(fd, content.encode("utf-8"))
    finally:
        os.close(fd)
    os.chmod(path, 0o600)
    return path


async def _bridge(
    local_reader: asyncio.StreamReader,
    local_writer: asyncio.StreamWriter,
    upstream_reader: asyncio.StreamReader,
    upstream_writer: asyncio.StreamWriter,
) -> None:
    async def copy(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
        try:
            while True:
                data = await src.read(4096)
                if not data:
                    break
                dst.write(data)
                await dst.drain()
        except Exception:
            # Peer closed, bridge tears down below.
            pass
        finally:
            try:
                dst.close()
            except Exception:
                pass

    await asyncio.gather(
        copy(local_reader, upstream_writer),
        copy(upstream_reader, local_writer),
        return_exceptions=True,
    )


def register(forwarder: RaTlsForwarder) -> None:
    """Keep a module-level reference so Python's GC doesn't collect it."""
    _FORWARDERS.append(forwarder)


def registered() -> list[RaTlsForwarder]:
    """Currently-alive forwarders held by this module."""
    return list(_FORWARDERS)


__all__ = ["RaTlsForwarder", "register", "registered"]
