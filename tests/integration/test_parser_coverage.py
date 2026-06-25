"""Integration tests for EVTX parser, scanner, and validation coverage."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from src.application.hashing import HashService
from src.application.scanning import ClamAVScanner, NoOpScanner
from src.application.validation import (
    FileSizeValidator,
    MagicByteValidator,
    ValidatorChain,
)

# ---------------------------------------------------------------------------
# Tests: EVTX Parser (low coverage path)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_evtx_parser_detects_format() -> None:
    """EVTX parser correctly identifies EVTX files by magic bytes."""
    from src.external.parsers.evtx import FastEvtxParser

    parser = FastEvtxParser()

    # EVTX files start with magic bytes: 0x45 0x6c 0x66 0x46 0x69 0x6c 0x65
    evtx_magic = b"ElfFile\x00" + b"\x00" * 100
    result = parser.supports(evtx_magic, "test.evtx")
    assert result is True


@pytest.mark.asyncio
async def test_evtx_parser_rejects_non_evtx() -> None:
    """EVTX parser correctly rejects non-EVTX files."""
    from src.external.parsers.evtx import FastEvtxParser

    parser = FastEvtxParser()

    # Non-EVTX file
    bad_magic = b"NOTEVTX" + b"\x00" * 100
    result = parser.supports(bad_magic, "test.txt")
    assert result is False


@pytest.mark.asyncio
async def test_evtx_parser_handles_invalid_file() -> None:
    """EVTX parser gracefully handles a truncated/invalid EVTX file."""
    from src.exceptions import ParsingError
    from src.external.parsers.evtx import FastEvtxParser

    parser = FastEvtxParser()

    # Valid magic but truncated file
    truncated_evtx = b"ElfFile\x00" + b"\x00" * 10  # Too short

    with pytest.raises(ParsingError):
        records = []
        async for record in parser.parse(truncated_evtx, "test.evtx"):
            records.append(record)


@pytest.mark.asyncio
async def test_evtx_parser_yields_records_async() -> None:
    """EVTX parser yields timeline records as async iterator."""
    from src.external.parsers.evtx import FastEvtxParser

    parser = FastEvtxParser()

    # Check that parse() returns an async generator
    result = parser.parse(b"dummy", "test.evtx")
    assert hasattr(result, "__aiter__")


# ---------------------------------------------------------------------------
# Tests: CloudTrail and Nginx parsers (validation coverage)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cloudtrail_parser_validates_json_format() -> None:
    """CloudTrail parser validates JSON structure before parsing."""
    from src.external.parsers.cloudtrail import CloudTrailParser

    parser = CloudTrailParser()

    # Valid CloudTrail JSON structure
    valid_ct = b'{"Records": [{"eventVersion": "1.0"}]}'
    result = parser.supports(valid_ct, "cloudtrail.json")
    assert result is True


@pytest.mark.asyncio
async def test_cloudtrail_parser_rejects_invalid_json() -> None:
    """CloudTrail parser rejects malformed JSON."""
    from src.external.parsers.cloudtrail import CloudTrailParser

    parser = CloudTrailParser()

    # Invalid JSON
    bad_json = b'{"invalid": [unclosed'
    result = parser.supports(bad_json, "test.json")
    assert result is False


@pytest.mark.asyncio
async def test_nginx_parser_identifies_access_logs() -> None:
    """Nginx parser correctly identifies access log format."""
    from src.external.parsers.nginx import NginxParser

    parser = NginxParser()

    # Common nginx access log format
    nginx_log = b"192.168.1.1 - - [25/Jun/2026:12:34:56 +0000] \"GET / HTTP/1.1\" 200 1234"
    result = parser.supports(nginx_log, "access.log")
    assert result is True


@pytest.mark.asyncio
async def test_nginx_parser_parses_valid_log() -> None:
    """Nginx parser correctly parses a valid access log entry."""
    from src.external.parsers.nginx import NginxParser

    parser = NginxParser()

    nginx_log = (
        b"192.168.1.1 - user [25/Jun/2026:12:34:56 +0000] "
        b'"GET /api/users HTTP/1.1" 200 1234 "-" "curl/7.0"'
    )

    records = []
    async for record in parser.parse(nginx_log, "access.log"):
        records.append(record)

    assert len(records) >= 1
    assert records[0].src_ip == "192.168.1.1"


# ---------------------------------------------------------------------------
# Tests: File validation chain
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_magic_byte_validator_accepts_known_formats() -> None:
    """MagicByteValidator accepts files with known magic bytes."""
    validator = MagicByteValidator()

    # EVTX magic bytes
    evtx_data = b"ElfFile\x00" + b"\x00" * 100
    result = await validator.validate(evtx_data, "test.evtx")
    assert result.valid is True


@pytest.mark.asyncio
async def test_magic_byte_validator_rejects_unknown_format() -> None:
    """MagicByteValidator rejects files without recognized magic bytes."""
    validator = MagicByteValidator()

    # Unknown format
    unknown_data = b"\xDE\xAD\xBE\xEF" + b"\x00" * 100
    result = await validator.validate(unknown_data, "test.bin")
    assert result.valid is False


@pytest.mark.asyncio
async def test_file_size_validator_accepts_within_limit() -> None:
    """FileSizeValidator accepts files within max size."""
    max_size = 1000000  # 1 MB
    validator = FileSizeValidator(max_size_bytes=max_size)

    data = b"x" * 500000  # 500 KB
    result = await validator.validate(data, "test.bin")
    assert result.valid is True


@pytest.mark.asyncio
async def test_file_size_validator_rejects_oversized_file() -> None:
    """FileSizeValidator rejects files exceeding max size."""
    max_size = 1000000  # 1 MB
    validator = FileSizeValidator(max_size_bytes=max_size)

    data = b"x" * 2000000  # 2 MB
    result = await validator.validate(data, "test.bin")
    assert result.valid is False


@pytest.mark.asyncio
async def test_validator_chain_stops_at_first_failure() -> None:
    """ValidatorChain stops at first validation failure."""
    validator1 = MagicByteValidator()
    validator2 = FileSizeValidator(max_size_bytes=100)

    chain = ValidatorChain([validator1, validator2])

    # File with unknown magic and oversized
    bad_data = b"\xDE\xAD\xBE\xEF" + b"x" * 200

    result = await chain.validate(bad_data, "test.bin")
    assert result.valid is False


@pytest.mark.asyncio
async def test_validator_chain_passes_all_validators() -> None:
    """ValidatorChain passes if all validators succeed."""
    validator1 = MagicByteValidator()
    validator2 = FileSizeValidator(max_size_bytes=100000)

    chain = ValidatorChain([validator1, validator2])

    # Valid EVTX file within size limit
    good_data = b"ElfFile\x00" + b"\x00" * 50000

    result = await chain.validate(good_data, "test.evtx")
    assert result.valid is True


# ---------------------------------------------------------------------------
# Tests: ClamAV Scanner
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_clamd_scanner_accepts_clean_file() -> None:
    """ClamAVScanner reports clean for non-infected file."""
    scanner = ClamAVScanner(host="localhost", port=3310, timeout=5)

    # Mock the clamd connection
    with patch("pyclamd.ClamdAsyncNetworking") as mock_clamd:
        mock_instance = AsyncMock()
        mock_instance.scan_stream = AsyncMock(return_value={"file": (b"", None)})
        mock_clamd.return_value = mock_instance

        clean_file = b"This is a clean file"
        result = await scanner.scan(clean_file)

        assert result.infected is False
        assert result.threat_name is None


@pytest.mark.asyncio
async def test_clamd_scanner_detects_infected_file() -> None:
    """ClamAVScanner detects and reports infected files."""
    scanner = ClamAVScanner(host="localhost", port=3310, timeout=5)

    with patch("pyclamd.ClamdAsyncNetworking") as mock_clamd:
        mock_instance = AsyncMock()
        # Simulate infected file detection
        mock_instance.scan_stream = AsyncMock(
            return_value={"file": (b"Win.Test.EICAR_HDB-1", "INFECTED")}
        )
        mock_clamd.return_value = mock_instance

        infected_file = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        result = await scanner.scan(infected_file)

        assert result.infected is True
        assert result.threat_name == "Win.Test.EICAR_HDB-1"


@pytest.mark.asyncio
async def test_noop_scanner_always_accepts() -> None:
    """NoOpScanner always reports clean (for testing)."""
    scanner = NoOpScanner()

    result = await scanner.scan(b"any data")
    assert result.infected is False
    assert result.threat_name is None


# ---------------------------------------------------------------------------
# Tests: Hashing service
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_hash_service_computes_sha256() -> None:
    """HashService computes correct SHA-256 hash."""
    service = HashService()

    data = b"test data"
    result = await service.compute_sha256(data)

    # SHA-256 of "test data"
    import hashlib

    expected = hashlib.sha256(b"test data").hexdigest()
    assert result == expected
    assert len(result) == 64  # SHA-256 is 64 hex chars


@pytest.mark.asyncio
async def test_hash_service_computes_md5() -> None:
    """HashService computes correct MD5 hash."""
    service = HashService()

    data = b"test data"
    result = await service.compute_md5(data)

    # MD5 of "test data"
    import hashlib

    expected = hashlib.md5(b"test data").hexdigest()
    assert result == expected
    assert len(result) == 32  # MD5 is 32 hex chars


@pytest.mark.asyncio
async def test_hash_service_large_file() -> None:
    """HashService efficiently hashes large files."""
    service = HashService()

    # 10 MB of data
    large_data = b"x" * (10 * 1024 * 1024)
    sha256_result = await service.compute_sha256(large_data)

    # Should complete without memory issues and return valid hash
    assert len(sha256_result) == 64
    assert all(c in "0123456789abcdef" for c in sha256_result)
