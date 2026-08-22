"""Unit tests for migrations/db_url.py's DATABASE_URL/DATABASE_URL_FILE resolution.

Gap Audit Milestone MM: db-migrate's `alembic upgrade head` command bypasses
`src.config.Settings()` entirely (migrations/env.py reads DATABASE_URL
directly, on purpose -- see that module's own docstring), so Settings()'s new
secrets_dir support (tests/unit/test_config.py) does not help this specific
service. `resolve_database_url()` gets its own fix + tests instead: a
DATABASE_URL_FILE fallback, mirroring the official postgres image's own
POSTGRES_PASSWORD_FILE convention already used elsewhere in
docker-compose.prod.yml.

This function is deliberately extracted into its own module (not left inline
in migrations/env.py) because env.py imports `alembic.context` at module
level, which is an unconfigured proxy outside a real `alembic` invocation --
confirmed directly: a plain `import migrations.env` raises
`AttributeError: module 'alembic.context' has no attribute 'config'`. That
makes env.py itself unsafe to import from a unit test, so the one real,
independently-testable behaviour (env var vs. file resolution) lives here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from migrations.db_url import resolve_database_url

_DSN = "postgresql+asyncpg://kronos:pw1@postgres:5432/kronos"


class TestPlainEnvVarPathUnchanged:
    def test_database_url_env_var_resolves_directly(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DATABASE_URL", _DSN)
        monkeypatch.delenv("DATABASE_URL_FILE", raising=False)

        assert resolve_database_url() == _DSN

    def test_database_url_env_var_wins_over_file(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        secret_file = tmp_path / "database_url"
        secret_file.write_text("postgresql+asyncpg://from-file/should-not-win")
        monkeypatch.setenv("DATABASE_URL", _DSN)
        monkeypatch.setenv("DATABASE_URL_FILE", str(secret_file))

        assert resolve_database_url() == _DSN


class TestSecretFilePath:
    def test_resolves_from_real_secret_file(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        secret_file = tmp_path / "database_url"
        secret_file.write_text(_DSN)
        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.setenv("DATABASE_URL_FILE", str(secret_file))

        assert resolve_database_url() == _DSN

    def test_secret_file_content_is_stripped(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        secret_file = tmp_path / "database_url"
        secret_file.write_text(_DSN + "\n")
        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.setenv("DATABASE_URL_FILE", str(secret_file))

        assert resolve_database_url() == _DSN


class TestMissingOrEmptyRaisesClearly:
    def test_neither_env_var_nor_file_set_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.delenv("DATABASE_URL_FILE", raising=False)

        with pytest.raises(RuntimeError, match="DATABASE_URL"):
            resolve_database_url()

    def test_database_url_file_points_at_nonexistent_path_raises_clearly(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.setenv("DATABASE_URL_FILE", str(tmp_path / "does-not-exist"))

        with pytest.raises(RuntimeError, match="does not exist"):
            resolve_database_url()

    @pytest.mark.parametrize("blank_content", ["", "   ", "\n"])
    def test_empty_secret_file_raises_clearly_not_blank_dsn(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, blank_content: str
    ) -> None:
        secret_file = tmp_path / "database_url"
        secret_file.write_text(blank_content)
        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.setenv("DATABASE_URL_FILE", str(secret_file))

        with pytest.raises(RuntimeError, match="empty"):
            resolve_database_url()

    def test_blank_database_url_env_var_falls_back_to_file(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """A whitespace-only DATABASE_URL must not shadow a real DATABASE_URL_FILE."""
        secret_file = tmp_path / "database_url"
        secret_file.write_text(_DSN)
        monkeypatch.setenv("DATABASE_URL", "   ")
        monkeypatch.setenv("DATABASE_URL_FILE", str(secret_file))

        assert resolve_database_url() == _DSN
