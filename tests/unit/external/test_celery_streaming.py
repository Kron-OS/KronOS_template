"""Unit tests for src.external.celery_streaming (roadmap Milestone W/W1).

Mirrors test_celery_defender.py's own precedent exactly: the real,
full-cycle success path (real Redis stream discovery, real Postgres/MinIO/
OpenSearch/Keycloak round trips) is verified end-to-end, for real, in
poc/autonomous_detection_pipeline/ (CLAUDE.md SS F) -- not re-mocked here.
Unlike celery_defender.py, this module has no "honestly not configured"
short-circuit branch to unit test in isolation (seal_pending_streams/
sync_detection_findings always attempt real discovery, gracefully
returning empty results when there's nothing to do rather than refusing to
run) -- so these tests instead cover the module's own small, pure helper
functions, which are exactly the parts NOT already covered by the real
PoC's own end-to-end assertions.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from src.external.celery_streaming import (
    OrgAliasNotFoundError,
    _minio_endpoint_url,
    _stream_redis_url,
)


def _fake_secret(value: str) -> MagicMock:
    secret = MagicMock()
    secret.get_secret_value.return_value = value
    return secret


class TestMinioEndpointUrl:
    def test_tls_enabled_uses_https(self) -> None:
        settings = SimpleNamespace(minio_use_tls=True, minio_endpoint="minio:9000")
        assert _minio_endpoint_url(settings) == "https://minio:9000"

    def test_tls_disabled_uses_http(self) -> None:
        settings = SimpleNamespace(minio_use_tls=False, minio_endpoint="localhost:9000")
        assert _minio_endpoint_url(settings) == "http://localhost:9000"


class TestStreamRedisUrl:
    def test_rewrites_path_to_the_configured_stream_db(self) -> None:
        settings = SimpleNamespace(
            redis_url=_fake_secret("redis://redis:6379/1"), stream_redis_db=3
        )
        assert _stream_redis_url(settings) == "redis://redis:6379/3"

    def test_preserves_host_and_scheme(self) -> None:
        settings = SimpleNamespace(
            redis_url=_fake_secret("redis://:password@myredis:6380/0"), stream_redis_db=7
        )
        assert _stream_redis_url(settings) == "redis://:password@myredis:6380/7"


class TestOrgAliasNotFoundError:
    def test_is_a_real_runtime_error_not_an_honest_skip_type(self) -> None:
        # Unlike DefenderPollNotConfiguredError (an honest, expected
        # pre-production no-op the calling Celery task treats as a silent
        # skip), this must be a plain RuntimeError so it falls through to
        # the calling task's generic except/retry branch and surfaces
        # loudly (CLAUDE.md invariant #8) -- see this class's own docstring.
        assert issubclass(OrgAliasNotFoundError, RuntimeError)
        exc = OrgAliasNotFoundError("org disappeared")
        assert str(exc) == "org disappeared"
