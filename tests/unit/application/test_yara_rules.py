"""Unit tests for YaraRuleProvider/DirectoryYaraRuleProvider (roadmap M4/E3)."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.application.yara_rules import DirectoryYaraRuleProvider


class TestDirectoryYaraRuleProvider:
    @pytest.mark.asyncio
    async def test_missing_directory_returns_none(self, tmp_path: Path) -> None:
        provider = DirectoryYaraRuleProvider(tmp_path / "does-not-exist")

        assert await provider.get_rule_source() is None

    @pytest.mark.asyncio
    async def test_empty_directory_returns_none(self, tmp_path: Path) -> None:
        provider = DirectoryYaraRuleProvider(tmp_path)

        assert await provider.get_rule_source() is None

    @pytest.mark.asyncio
    async def test_ignores_non_yar_files(self, tmp_path: Path) -> None:
        (tmp_path / "readme.txt").write_text("not a rule")
        provider = DirectoryYaraRuleProvider(tmp_path)

        assert await provider.get_rule_source() is None

    @pytest.mark.asyncio
    async def test_concatenates_every_yar_file_in_sorted_order(self, tmp_path: Path) -> None:
        (tmp_path / "b_second.yar").write_text("rule second { condition: true }")
        (tmp_path / "a_first.yar").write_text("rule first { condition: true }")
        provider = DirectoryYaraRuleProvider(tmp_path)

        source = await provider.get_rule_source()

        assert source is not None
        assert source.index("rule first") < source.index("rule second")

    @pytest.mark.asyncio
    async def test_unreadable_file_is_skipped_not_fatal(self, tmp_path: Path) -> None:
        good = tmp_path / "good.yar"
        good.write_text("rule good { condition: true }")
        bad_dir_as_file = tmp_path / "bad.yar"
        bad_dir_as_file.mkdir()  # a directory named *.yar -- read_text() will raise

        source = await DirectoryYaraRuleProvider(tmp_path).get_rule_source()

        assert source is not None
        assert "rule good" in source
