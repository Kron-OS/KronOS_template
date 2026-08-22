"""Unit tests for src.config.Settings' secrets_dir / plain-env-var DSN resolution.

Gap Audit Milestone MM: `docker-compose.prod.yml` used to bake resolved
Postgres/Redis DSNs (plaintext passwords) directly into kronos-backend/
celery-worker/db-migrate's `environment:` block, visible verbatim via
`docker inspect --format '{{json .Config.Env}}'` (see
poc/backend_prod_secret_config_env_exposure/). The fix adds pydantic-settings
2.14.2's real `secrets_dir` SettingsConfigDict option so the four DSN fields
below can instead resolve from mounted Docker secret files. These tests prove:
(i) the existing plain-env-var path is completely unchanged, (ii) the new
secrets_dir path correctly resolves a real DSN from a real temp file, (iii) a
missing or empty secret file raises a clear, loud ValidationError rather than
silently producing a broken connection string.

No test in this repo constructs a fully-valid real `Settings()` today (every
other unit test either patches `src.config.Settings` or exercises a single
failure path — see test_splunk_hec_sink_wiring.py's own module docstring for
why) since Settings() requires ~15 unrelated required fields. This module is
the first to actually build one for real, so it defines its own minimal
complete set of required kwargs rather than reusing a nonexistent shared
fixture.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from src.config import Settings

# The full set of Settings() fields with no default -- every field below
# must be supplied (via env, secrets_dir file, or init kwarg) or Settings()
# raises. Kept separate from the four DSN fields under test so each test can
# override just those four without repeating the other eleven.
_OTHER_REQUIRED_KWARGS: dict[str, str] = {
    "minio_endpoint": "minio:9000",
    "minio_access_key": "test-access-key",
    "minio_secret_key": "test-secret-key",
    "opensearch_url": "https://opensearch:9200",
    "opensearch_username": "kronos_backend",
    "opensearch_password": "test-opensearch-password",
    "keycloak_url": "https://keycloak.example.com",
    "keycloak_client_secret": "test-keycloak-secret",
    "vault_url": "https://vault:8200",
    "vault_token": "test-vault-token",
}

_DSN_FIELDS = ("database_url", "redis_url", "celery_broker_url", "celery_result_backend")


def _dsn_value(field_name: str) -> str:
    """A distinct, realistic-shaped DSN per field so assertions can't false-positive."""
    return {
        "database_url": "postgresql+asyncpg://kronos:pw1@postgres:5432/kronos",
        "redis_url": "redis://:pw2@redis-auth-streams:6379/0",
        "celery_broker_url": "redis://:pw3@redis-celery:6379/1",
        "celery_result_backend": "redis://:pw3@redis-celery:6379/2",
    }[field_name]


class TestPlainEnvVarPathUnchanged:
    """(i) Existing docker-compose.dev.yml-style plain env vars still work as before."""

    def test_all_four_dsn_fields_resolve_from_plain_env_vars(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for field in _DSN_FIELDS:
            monkeypatch.setenv(field.upper(), _dsn_value(field))

        settings = Settings(_env_file=None, **_OTHER_REQUIRED_KWARGS)  # type: ignore[call-arg]

        for field in _DSN_FIELDS:
            assert getattr(settings, field).get_secret_value() == _dsn_value(field)
            # SecretStr must not leak the plaintext DSN via repr/str.
            assert _dsn_value(field) not in repr(getattr(settings, field))

    def test_secrets_dir_unset_by_default_does_not_touch_plain_env_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """KRONOS_SECRETS_DIR unset (dev's real state) -- model_config.secrets_dir is None."""
        monkeypatch.delenv("KRONOS_SECRETS_DIR", raising=False)
        assert Settings.model_config.get("secrets_dir") is None


class TestSecretsDirPath:
    """(ii) The new Docker/Kubernetes-secrets-style file resolution path."""

    def test_dsn_resolves_from_real_secret_file(self, tmp_path: Path) -> None:
        for field in _DSN_FIELDS:
            (tmp_path / field).write_text(_dsn_value(field))

        settings = Settings(
            _env_file=None,  # type: ignore[call-arg]
            _secrets_dir=tmp_path,  # type: ignore[call-arg]
            **_OTHER_REQUIRED_KWARGS,
        )

        for field in _DSN_FIELDS:
            assert getattr(settings, field).get_secret_value() == _dsn_value(field)

    def test_secret_file_content_is_stripped(self, tmp_path: Path) -> None:
        """Docker secret files commonly carry a trailing newline -- must not leak into the DSN."""
        for field in _DSN_FIELDS:
            (tmp_path / field).write_text(_dsn_value(field) + "\n")

        settings = Settings(
            _env_file=None,  # type: ignore[call-arg]
            _secrets_dir=tmp_path,  # type: ignore[call-arg]
            **_OTHER_REQUIRED_KWARGS,
        )

        assert settings.database_url.get_secret_value() == _dsn_value("database_url")

    def test_plain_env_var_still_wins_over_secrets_dir_file(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Real pydantic-settings source-priority order: env beats file secrets.

        Not exercised by production (the fix removes the plaintext env var
        entirely once secrets_dir is adopted for a field) but worth locking
        down: an operator who forgets to remove a stray plaintext env var
        during migration gets the ENV value, not a silently-different file
        value -- an explicit, discoverable state rather than two disagreeing
        sources merging unpredictably.
        """
        (tmp_path / "database_url").write_text("postgresql+asyncpg://from-file/should-not-win")
        monkeypatch.setenv("DATABASE_URL", _dsn_value("database_url"))
        for field in ("redis_url", "celery_broker_url", "celery_result_backend"):
            (tmp_path / field).write_text(_dsn_value(field))

        settings = Settings(
            _env_file=None,  # type: ignore[call-arg]
            _secrets_dir=tmp_path,  # type: ignore[call-arg]
            **_OTHER_REQUIRED_KWARGS,
        )

        assert settings.database_url.get_secret_value() == _dsn_value("database_url")


class TestMissingOrEmptySecretRaisesClearly:
    """(iii) Missing/empty secret material fails loudly, never silently."""

    def test_missing_secrets_dir_file_raises_field_required(self, tmp_path: Path) -> None:
        # secrets_dir exists but has none of the four expected files, and no
        # plain env var is set either -- pydantic's own pre-existing
        # "field required" behaviour must still fire.
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                _env_file=None,  # type: ignore[call-arg]
                _secrets_dir=tmp_path,  # type: ignore[call-arg]
                **_OTHER_REQUIRED_KWARGS,
            )

        errors = {e["loc"][0] for e in exc_info.value.errors()}
        assert set(_DSN_FIELDS) <= errors

    def test_nonexistent_secrets_dir_raises_field_required(self, tmp_path: Path) -> None:
        missing_dir = tmp_path / "does-not-exist"
        with pytest.raises(ValidationError):
            Settings(
                _env_file=None,  # type: ignore[call-arg]
                _secrets_dir=missing_dir,  # type: ignore[call-arg]
                **_OTHER_REQUIRED_KWARGS,
            )

    @pytest.mark.parametrize("blank_content", ["", "   ", "\n"])
    def test_empty_secret_file_raises_clear_error_not_blank_dsn(
        self, tmp_path: Path, blank_content: str
    ) -> None:
        """A secret file that exists but is blank must not silently become an empty DSN.

        This is the one gap secrets_dir's own file-lookup contract leaves
        open (present-but-empty resolves to "", a syntactically valid str
        that would otherwise sail past pydantic's "field required" check) --
        closed by Settings._reject_blank_dsn.
        """
        (tmp_path / "database_url").write_text(blank_content)
        for field in ("redis_url", "celery_broker_url", "celery_result_backend"):
            (tmp_path / field).write_text(_dsn_value(field))

        with pytest.raises(ValidationError) as exc_info:
            Settings(
                _env_file=None,  # type: ignore[call-arg]
                _secrets_dir=tmp_path,  # type: ignore[call-arg]
                **_OTHER_REQUIRED_KWARGS,
            )

        assert "database_url" in str(exc_info.value)
        assert "empty" in str(exc_info.value).lower()

    def test_empty_plain_env_var_also_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The same guard applies to the plain-env-var path, not just secrets_dir."""
        monkeypatch.setenv("DATABASE_URL", "   ")
        monkeypatch.setenv("REDIS_URL", _dsn_value("redis_url"))
        monkeypatch.setenv("CELERY_BROKER_URL", _dsn_value("celery_broker_url"))
        monkeypatch.setenv("CELERY_RESULT_BACKEND", _dsn_value("celery_result_backend"))

        with pytest.raises(ValidationError) as exc_info:
            Settings(_env_file=None, **_OTHER_REQUIRED_KWARGS)  # type: ignore[call-arg]

        assert "database_url" in str(exc_info.value)
