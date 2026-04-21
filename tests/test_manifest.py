"""Manifest verifier unit tests.

The canonical body format is also tested in the Rust controller crate
(crates/dns-controller/src/manifest.rs). The two implementations MUST agree
byte-for-byte; the golden-string test below pins the exact pre-signing bytes
so a drift between the two surfaces as a failure in both test suites.
"""

import time

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct

from psycopg_ratls.manifest import Manifest, ManifestError, parse_and_verify

FIXTURE_PRIVATE_KEY = "0x" + "11" * 32
# Address derived from the above private key via secp256k1 + keccak256(X||Y)[-20:].
FIXTURE_SIGNER_ADDRESS = bytes.fromhex(Account.from_key(FIXTURE_PRIVATE_KEY).address[2:])


def _fixture_manifest() -> Manifest:
    return Manifest(
        cluster="0xbd32b609057a1a4569558a571d535c8f1212b097",
        leader_instance="ea23198e3419ebbb240571a29d0112d9bcbe69c0",
        leader_url="https://ea23198e3419ebbb240571a29d0112d9bcbe69c0-5433.dstack-base-prod9.phala.network",
        epoch=42,
        valid_until=int(time.time()) + 3600,
    )


def _sign(body: str) -> str:
    """Sign the canonical body with the fixture key and return 0x<65-byte hex>."""
    signed = Account.sign_message(encode_defunct(text=body), private_key=FIXTURE_PRIVATE_KEY)
    return "0x" + signed.signature.hex()


def test_canonical_body_golden_string():
    # This exact string must also be produced by the Rust controller's
    # manifest::Manifest::canonical_body(). If you change one side, update
    # the golden on the other side too.
    m = Manifest(
        cluster="0xbd32b609057a1a4569558a571d535c8f1212b097",
        leader_instance="ea23198e3419ebbb240571a29d0112d9bcbe69c0",
        leader_url="https://ea23198e3419ebbb240571a29d0112d9bcbe69c0-5433.dstack-base-prod9.phala.network",
        epoch=42,
        valid_until=1713312000,
    )
    expected = (
        "cluster=0xbd32b609057a1a4569558a571d535c8f1212b097;"
        "epoch=42;"
        "leader_instance=ea23198e3419ebbb240571a29d0112d9bcbe69c0;"
        "leader_url=https://ea23198e3419ebbb240571a29d0112d9bcbe69c0-5433.dstack-base-prod9.phala.network;"
        "v=1;"
        "valid_until=1713312000"
    )
    assert m.canonical_body() == expected


def test_sign_and_verify_roundtrip():
    m = _fixture_manifest()
    body = m.canonical_body()
    sig = _sign(body)
    txt = f"{body};sig={sig}"
    parsed = parse_and_verify(txt, FIXTURE_SIGNER_ADDRESS)
    assert parsed == m


def test_rejects_wrong_signer():
    m = _fixture_manifest()
    body = m.canonical_body()
    sig = _sign(body)
    txt = f"{body};sig={sig}"
    with pytest.raises(ManifestError, match="signer mismatch"):
        parse_and_verify(txt, bytes(20))


def test_rejects_tampered_body():
    m = _fixture_manifest()
    body = m.canonical_body()
    sig = _sign(body)
    # Swap the URL but keep the old signature.
    tampered = Manifest(
        cluster=m.cluster,
        leader_instance=m.leader_instance,
        leader_url="https://evil.example.com",
        epoch=m.epoch,
        valid_until=m.valid_until,
    )
    txt = f"{tampered.canonical_body()};sig={sig}"
    with pytest.raises(ManifestError, match="signer mismatch"):
        parse_and_verify(txt, FIXTURE_SIGNER_ADDRESS)


def test_rejects_expired_manifest():
    m = Manifest(
        cluster="0xbd32b609057a1a4569558a571d535c8f1212b097",
        leader_instance="ea23198e3419ebbb240571a29d0112d9bcbe69c0",
        leader_url="https://example.com",
        epoch=1,
        valid_until=1000,
    )
    body = m.canonical_body()
    sig = _sign(body)
    txt = f"{body};sig={sig}"
    with pytest.raises(ManifestError, match="expired"):
        parse_and_verify(txt, FIXTURE_SIGNER_ADDRESS, now=2000)


def test_rejects_wrong_version():
    m = _fixture_manifest()
    body = m.canonical_body().replace("v=1", "v=2")
    sig = _sign(body)
    txt = f"{body};sig={sig}"
    with pytest.raises(ManifestError, match="unsupported manifest version"):
        parse_and_verify(txt, FIXTURE_SIGNER_ADDRESS)


def test_rejects_short_sig():
    m = _fixture_manifest()
    body = m.canonical_body()
    txt = f"{body};sig=0xdeadbeef"
    with pytest.raises(ManifestError, match="sig must be 65 bytes"):
        parse_and_verify(txt, FIXTURE_SIGNER_ADDRESS)


def test_rejects_missing_sig():
    m = _fixture_manifest()
    body = m.canonical_body()
    with pytest.raises(ManifestError, match="missing sig field"):
        parse_and_verify(body, FIXTURE_SIGNER_ADDRESS)
