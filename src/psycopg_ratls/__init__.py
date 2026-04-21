"""psycopg3 connection with RA-TLS attestation verification for dstack TEE databases."""

from .connect import connect, connect_async, create_ssl_context
from .connect_manifest import (
    connect_via_manifest,
    connect_via_manifest_async,
    resolve_leader,
)
from .manifest import Manifest, ManifestError, parse_and_verify

__all__ = [
    "connect",
    "connect_async",
    "create_ssl_context",
    "connect_via_manifest",
    "connect_via_manifest_async",
    "resolve_leader",
    "Manifest",
    "ManifestError",
    "parse_and_verify",
]
