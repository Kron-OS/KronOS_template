"""Unit tests for X509SanCollectorIdentityExtractor.

Real step-ca-issued certs are exercised for real in
poc/collector_ingest_mtls/ (17/17 checks) -- these tests cover this class's
own SAN-parsing contract using certs generated in-process via `cryptography`
(no step-ca/network dependency needed for a unit test)."""

from __future__ import annotations

import datetime
import uuid

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from src.exceptions import AuthenticationError
from src.external.middleware.collector_mtls import X509SanCollectorIdentityExtractor


def _make_cert(sans: list[x509.GeneralName] | None) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test-collector")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1))
    )
    if sans is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(encoding=serialization.Encoding.DER)


class TestExtract:
    def test_valid_urn_san_yields_correct_identity(self) -> None:
        org_id = uuid.uuid4()
        der = _make_cert([x509.UniformResourceIdentifier(f"urn:kronos:collector:org:{org_id}:source:zeek-conn")])

        identity = X509SanCollectorIdentityExtractor().extract(der)

        assert identity.org_id == org_id
        assert identity.source_id == "zeek-conn"
        assert identity.cert_subject == "CN=test-collector"

    def test_no_san_extension_at_all_raises(self) -> None:
        der = _make_cert(None)
        with pytest.raises(AuthenticationError, match="no.*SAN"):
            X509SanCollectorIdentityExtractor().extract(der)

    def test_san_present_but_no_matching_urn_raises(self) -> None:
        der = _make_cert([x509.DNSName("some-hostname.example.com")])
        with pytest.raises(AuthenticationError, match="no.*SAN"):
            X509SanCollectorIdentityExtractor().extract(der)

    def test_malformed_org_id_in_san_raises(self) -> None:
        # Exactly 36 chars of [0-9a-fA-F-] (matches _URN_PATTERN's org_id
        # group) but not a syntactically valid UUID -- reaches uuid.UUID()'s
        # own ValueError branch, not the "no matching URN at all" case.
        bad_org_id = "-" * 34 + "00"
        der = _make_cert([x509.UniformResourceIdentifier(f"urn:kronos:collector:org:{bad_org_id}:source:x")])
        with pytest.raises(AuthenticationError, match="malformed org_id"):
            X509SanCollectorIdentityExtractor().extract(der)

    def test_malformed_der_bytes_raise(self) -> None:
        with pytest.raises(AuthenticationError, match="Malformed"):
            X509SanCollectorIdentityExtractor().extract(b"not a real certificate")

    def test_source_id_with_colons_is_captured_in_full(self) -> None:
        """The URN pattern's source_id group is greedy -- confirm a
        source_id containing its own colons round-trips correctly."""
        org_id = uuid.uuid4()
        der = _make_cert([x509.UniformResourceIdentifier(f"urn:kronos:collector:org:{org_id}:source:edr:vendor-x:host42")])

        identity = X509SanCollectorIdentityExtractor().extract(der)

        assert identity.source_id == "edr:vendor-x:host42"
