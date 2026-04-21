"""Tests for DNS TXT helpers that don't require actual DNS resolution."""

import pytest

from psycopg_ratls.discovery import build_record_name, postgres_host_from_leader_url


def test_build_record_name_prepends_label():
    assert build_record_name("monitor.teesql.com") == "_teesql-leader.monitor.teesql.com"


def test_build_record_name_is_idempotent():
    already = "_teesql-leader.monitor.teesql.com"
    assert build_record_name(already) == already


def test_postgres_host_from_https_leader_url():
    host, port = postgres_host_from_leader_url(
        "https://ea23198e3419ebbb240571a29d0112d9bcbe69c0-5433.dstack-base-prod9.phala.network"
    )
    assert host == "ea23198e3419ebbb240571a29d0112d9bcbe69c0-5433.dstack-base-prod9.phala.network"
    assert port == 443


def test_postgres_host_with_explicit_port():
    host, port = postgres_host_from_leader_url("https://db.example.com:5432")
    assert host == "db.example.com"
    assert port == 5432


def test_postgres_host_from_http_leader_url_uses_80():
    host, port = postgres_host_from_leader_url("http://db.example.com")
    assert host == "db.example.com"
    assert port == 80


def test_missing_hostname_raises():
    with pytest.raises(ValueError):
        postgres_host_from_leader_url("https://")
