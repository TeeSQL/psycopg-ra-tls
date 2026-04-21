"""Signed DNS TXT manifest — verifier that mirrors the Rust
teesql-dns-controller byte-for-byte.

Wire form (one logical TXT body):
    v=1;cluster=0x<addr>;leader_instance=<hex>;leader_url=<url>;
    epoch=<uint>;valid_until=<unix>;sig=0x<65-byte hex>

Canonical signing form: drop ``sig=``, lexically sort remaining key=value
pairs, join with ``;``, prefix with EIP-191 (``\\x19Ethereum Signed
Message:\\n<len>``), keccak256, sign. Verifier recovers the pubkey from the
signature and checks that the last 20 bytes of keccak256(X||Y) match the
trusted signer address.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from eth_account.messages import encode_defunct
from eth_account import Account

MANIFEST_VERSION = "1"


@dataclass(frozen=True)
class Manifest:
    cluster: str  # "0x..." lowercase
    leader_instance: str  # 64 hex chars, no 0x
    leader_url: str  # verbatim UTF-8
    epoch: int
    valid_until: int  # unix seconds

    def canonical_body(self) -> str:
        """Alphabetical key order: cluster, epoch, leader_instance, leader_url,
        v, valid_until. ``v`` sorts between ``leader_url`` and ``valid_until``."""
        parts = [
            ("cluster", self.cluster.lower()),
            ("epoch", str(self.epoch)),
            ("leader_instance", self.leader_instance.lower()),
            ("leader_url", self.leader_url),
            ("v", MANIFEST_VERSION),
            ("valid_until", str(self.valid_until)),
        ]
        return ";".join(f"{k}={v}" for k, v in parts)


class ManifestError(Exception):
    """Raised when a manifest TXT is malformed, stale, or improperly signed."""


def parse_and_verify(txt: str, expected_signer: bytes, *, now: int | None = None) -> Manifest:
    """Parse a TXT body, verify its EIP-191 signature against ``expected_signer``
    (20-byte ethereum-style address), check ``valid_until``, and return the
    parsed manifest.

    ``expected_signer`` is the manifest-signer address baked into the SDK at
    build time — the one derived from the dns-controller's KMS-derived
    secp256k1 key.
    """
    if len(expected_signer) != 20:
        raise ValueError("expected_signer must be 20 bytes")

    raw_parts = [p.strip() for p in txt.split(";") if p.strip()]
    parts: dict[str, str] = {}
    for p in raw_parts:
        if "=" not in p:
            raise ManifestError(f"malformed field: {p}")
        k, v = p.split("=", 1)
        parts[k.strip()] = v.strip()

    sig_hex = parts.pop("sig", None)
    if sig_hex is None:
        raise ManifestError("missing sig field")

    def require(key: str) -> str:
        if key not in parts:
            raise ManifestError(f"missing field {key}")
        return parts[key]

    if require("v") != MANIFEST_VERSION:
        raise ManifestError(f"unsupported manifest version: {parts['v']}")

    try:
        epoch = int(require("epoch"))
        valid_until = int(require("valid_until"))
    except ValueError as e:
        raise ManifestError(f"non-integer field: {e}") from e

    manifest = Manifest(
        cluster=require("cluster").lower(),
        leader_instance=require("leader_instance").lower(),
        leader_url=require("leader_url"),
        epoch=epoch,
        valid_until=valid_until,
    )

    # EIP-191 recover. encode_defunct handles the "\x19Ethereum Signed
    # Message:\n<len>" wrap.
    body = manifest.canonical_body()
    encoded = encode_defunct(text=body)
    sig_raw = sig_hex[2:] if sig_hex.startswith("0x") else sig_hex
    try:
        sig_bytes = bytes.fromhex(sig_raw)
    except ValueError as e:
        raise ManifestError(f"sig is not hex: {e}") from e
    if len(sig_bytes) != 65:
        raise ManifestError(f"sig must be 65 bytes, got {len(sig_bytes)}")

    recovered = Account.recover_message(encoded, signature=sig_bytes)
    # Account.recover_message returns a checksummed 0x-prefixed hex address.
    recovered_bytes = bytes.fromhex(recovered[2:])
    if recovered_bytes != expected_signer:
        raise ManifestError(
            f"signer mismatch: recovered 0x{recovered_bytes.hex()} "
            f"expected 0x{expected_signer.hex()}"
        )

    now = now if now is not None else int(time.time())
    if manifest.valid_until <= now:
        raise ManifestError(
            f"manifest expired: valid_until={manifest.valid_until} now={now}"
        )
    return manifest
