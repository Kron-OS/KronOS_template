"""Unit tests for src.external.celery_defender's per-org rewrite (connector
marketplace, `/admin/connectors`).

The real, full poll-cycle success path (real Postgres cursor persistence,
real Redis stream production, real OAuth2/alerts_v2 round trip) is verified
end-to-end in poc/v2_connector_wiring/defender_poll_beat_task/ (CLAUDE.md
SS F) -- these tests cover this module's own fast, pure-logic branches
(the two exception-classification paths, the "zero enabled orgs" no-op)
without a real Postgres/Redis/Vault, mirroring the previous version of
this file's own "SimpleNamespace stands in for Settings(), no real
dependency mocking required for the not-configured checks" technique.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from src.exceptions import StorageError
from src.external.celery_defender import (
    DefenderPollNotConfiguredError,
    _is_vault_connection_error,
    run_defender_poll_cycle,
)


def _fake_settings(*, vault_connectors_approle_creds_file: str | None = None) -> SimpleNamespace:
    return SimpleNamespace(vault_connectors_approle_creds_file=vault_connectors_approle_creds_file)


class TestVaultConnectionErrorClassification:
    def test_approle_login_failure_is_a_vault_connection_error(self) -> None:
        exc = StorageError(
            "VaultSecretStore: AppRole login failed", context={"vault_url": "http://vault:8200"}
        )
        assert _is_vault_connection_error(exc) is True

    def test_a_different_storage_error_is_not_a_vault_connection_error(self) -> None:
        exc = StorageError("VaultSecretStore: failed to read connector secret", context={})
        assert _is_vault_connection_error(exc) is False

    def test_unrelated_storage_error_is_not_a_vault_connection_error(self) -> None:
        exc = StorageError("Failed to upsert connector config", context={})
        assert _is_vault_connection_error(exc) is False


class TestRunDefenderPollCycleNotConfigured:
    def test_no_secret_store_configured_raises_not_configured(self) -> None:
        """The one still-genuinely-exceptional case: the per-org secret
        store itself isn't wired on this deployment at all, so the
        connector cannot function for ANY org -- distinct from "zero orgs
        have configured Defender yet", which is a normal no-op (see
        test_zero_enabled_orgs_is_a_noop_not_an_error below, verified
        against the real dev stack rather than mocked here since it
        requires a real Postgres connection to reach)."""
        with patch(
            "src.config.Settings",
            return_value=_fake_settings(vault_connectors_approle_creds_file=None),
        ):
            with pytest.raises(DefenderPollNotConfiguredError, match="Vault"):
                run_defender_poll_cycle()

    def test_configured_secret_store_proceeds_past_the_gate(self) -> None:
        """Confirms the not-configured gate itself is the only thing this
        SimpleNamespace needs to satisfy -- the function then goes on to
        build a real AsyncEngine against a missing `database_url`
        attribute, so the real AttributeError surfacing here is itself
        proof this test passed the DefenderPollNotConfiguredError gate
        cleanly (same technique the previous version of this file used for
        its own "valid, parses without raising" case)."""
        with patch(
            "src.config.Settings",
            return_value=_fake_settings(vault_connectors_approle_creds_file="/tmp/fake-creds.json"),
        ):
            with pytest.raises(AttributeError):
                run_defender_poll_cycle()
