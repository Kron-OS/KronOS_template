"""Unit tests for CosignPackSignatureVerifier (mocked subprocess.run).

Real Cosign v3.1.2 behavior (bundle-based verify-blob, valid vs. tampered
content) is verified for real in poc/rule_pack_lifecycle/ -- these tests
cover this class's own error-handling contract (fail closed on any tool
error, never raise past the port boundary).
"""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

from src.adapter.signing.cosign_verifier import CosignPackSignatureVerifier


class TestVerify:
    def test_returncode_zero_means_verified(self) -> None:
        result = MagicMock(returncode=0, stderr=b"")
        with patch("subprocess.run", return_value=result) as mock_run:
            verifier = CosignPackSignatureVerifier(cosign_binary="cosign")
            assert verifier.verify(b"content", b"bundle-json-bytes", "/tmp/pub.key") is True
        args = mock_run.call_args[0][0]
        assert args[0] == "cosign"
        assert args[1] == "verify-blob"
        assert "--key" in args and "/tmp/pub.key" in args

    def test_nonzero_returncode_means_rejected(self) -> None:
        result = MagicMock(returncode=1, stderr=b"invalid signature")
        with patch("subprocess.run", return_value=result):
            verifier = CosignPackSignatureVerifier(cosign_binary="cosign")
            assert verifier.verify(b"content", b"bad-bundle", "/tmp/pub.key") is False

    def test_missing_cosign_binary_fails_closed_not_raised(self) -> None:
        with patch("subprocess.run", side_effect=OSError("cosign: command not found")):
            verifier = CosignPackSignatureVerifier(cosign_binary="cosign")
            assert verifier.verify(b"content", b"bundle", "/tmp/pub.key") is False

    def test_timeout_fails_closed_not_raised(self) -> None:
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="cosign", timeout=30)):
            verifier = CosignPackSignatureVerifier(cosign_binary="cosign")
            assert verifier.verify(b"content", b"bundle", "/tmp/pub.key") is False

    def test_never_returns_true_without_a_real_zero_returncode(self) -> None:
        for bad_code in (1, 2, 127, -1):
            result = MagicMock(returncode=bad_code, stderr=b"")
            with patch("subprocess.run", return_value=result):
                verifier = CosignPackSignatureVerifier(cosign_binary="cosign")
                assert verifier.verify(b"c", b"s", "/tmp/pub.key") is False
