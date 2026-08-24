"""Real Cosign CLI-backed PackSignatureVerifier.

Roadmap M2/C3. Shells out to the real, pinned local `cosign` binary
(v3.1.2, confirmed via `cosign version` -- see
poc/rule_pack_lifecycle/README.md for the exact captured output) using
`cosign verify-blob --bundle <bundle-file> --key <pub> <content-file>`.

Deliberately key-pair based (`cosign generate-key-pair` / `sign-blob
--key`), not the keyless-OIDC/Fulcio flow this repo's own CI uses for
container images (.github/workflows/build.yml's `cosign sign --yes`
without `--key`, which relies on GitHub Actions' own ambient OIDC token).
A rule-pack publisher signing content offline or in a non-GitHub-Actions
pipeline has no such ambient OIDC identity to present, so cosign's
long-supported key-pair blob-signing mode is the correct mode for this
artifact type -- not a downgrade of the trust model in
reviews/Extensibility_Architecture_Proposal.md SS4.1 (which describes
signing container *images* specifically; this class covers signing
arbitrary *content bytes*, which cosign only supports via sign-blob).

Real, empirically-confirmed shape of this cosign version's output (this
was NOT assumed from cosign's older docs, which describe a bare detached
`.sig` file -- v3.1.2 defaults to a self-contained JSON "bundle"):
`cosign sign-blob --key cosign.key --bundle pack.bundle <file>` writes a
single JSON file (`mediaType: application/vnd.dev.sigstore.bundle.v0.3+json`)
containing the signature AND a real Rekor transparency-log inclusion proof
-- even for pure key-pair signing, this cosign version uploads the entry to
the public `rekor.sigstore.dev` log by default (confirmed: signing requires
outbound network access to Rekor + a Sigstore-run RFC3161 TSA; this class's
own `verify()` call does not require network for a bundle that already
embeds its inclusion proof/checkpoint -- confirmed by a real verify-blob
run, see the PoC output). ``signature`` in this port's method signature is
therefore this whole bundle JSON's bytes, not a bare base64 signature --
documented here so a future maintainer isn't confused by the mismatch with
cosign's own older `--signature`/`.sig` terminology.
"""

from __future__ import annotations

import logging
import subprocess
import tempfile
from pathlib import Path

from src.application.pack_signing import PackSignatureVerifier

logger = logging.getLogger(__name__)


class CosignPackSignatureVerifier(PackSignatureVerifier):
    """Verifies a Cosign bundle (signature + Rekor proof) over rule-pack content."""

    def __init__(self, cosign_binary: str = "cosign", timeout_seconds: int = 30) -> None:
        self._cosign_binary = cosign_binary
        self._timeout_seconds = timeout_seconds

    def verify(self, content: bytes, signature: bytes, public_key_path: str) -> bool:
        with tempfile.TemporaryDirectory() as tmp:
            content_path = Path(tmp) / "pack.bin"
            bundle_path = Path(tmp) / "pack.bundle"
            try:
                # Gap Audit Milestone VV: these two writes used to sit
                # outside this try block, so a real OSError here (e.g. a
                # full disk) escaped verify() uncaught -- violating this
                # class's own documented "fail closed on any tool error,
                # never raise past the port boundary" contract (see this
                # file's own test suite). The caller (RulePackService/
                # YaraRulePackService.import_signed_pack) has no try/except
                # of its own around this call, so an uncaught exception here
                # meant a signature-rejection never reached the audit log at
                # all (RULE_PACK_SIGNATURE_REJECTED never fired) -- a
                # completely silent, unaudited rejection path, not merely an
                # unclean error response.
                content_path.write_bytes(content)
                bundle_path.write_bytes(signature)
                result = subprocess.run(  # noqa: S603
                    [
                        self._cosign_binary,
                        "verify-blob",
                        "--bundle",
                        str(bundle_path),
                        "--key",
                        public_key_path,
                        str(content_path),
                    ],
                    capture_output=True,
                    timeout=self._timeout_seconds,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                logger.warning("cosign_verify_tool_error", extra={"error": str(exc)})
                return False
            if result.returncode != 0:
                logger.info(
                    "cosign_verify_rejected",
                    extra={"stderr": result.stderr.decode(errors="replace")[:500]},
                )
                return False
            return True
