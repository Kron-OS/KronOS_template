"""Combined SQLAlchemy Core ``MetaData`` for Alembic autogenerate.

This repo does NOT have one shared SQLAlchemy declarative ``Base``/registry
(confirmed via a repo-wide grep before writing this): there are 14 separate
``src/adapter/repository/postgres_*.py`` modules, each with its own private
module-level ``_metadata = sa.MetaData()`` and its own ``sa.Table(...)`` Core
definitions, each consumed by that module's own ``create_tables(engine)``
classmethod (see ``src/adapter/repository/_schema_lock.py`` for why those
classmethods also take a Postgres advisory lock -- multiple app/worker
processes can call ``create_tables()`` concurrently at boot).

Alembic's autogenerate needs exactly ONE ``MetaData`` object to diff the
live database against. Rather than inventing a second, parallel registry
that the 14 repositories would have to remember to also register into (an
easy-to-forget step -- exactly the kind of gap that caused two of this
repo's own real, shipped bugs per ``create_tables()``'s own callers), this
module builds a throwaway COMBINED ``MetaData`` at import time by copying
each already-defined ``Table`` object into it via ``Table.tometadata()``.

Nothing here mutates any repository's own ``_metadata`` -- ``tometadata()``
returns a new ``Table`` bound to the target registry, leaving the source
table (and that repository's own ``create_tables()`` contract, still used
directly by ``tests/integration/conftest.py``) completely untouched.
"""

from __future__ import annotations

from types import ModuleType

import sqlalchemy as sa

# One entry per postgres_*.py repository module that defines its own
# `_metadata = sa.MetaData()` + `sa.Table(...)` pair (confirmed via
# `grep -rn "^_metadata = sa.MetaData()" src/adapter/repository/*.py` --
# 14 modules, matching this list exactly). Add a new module here the same
# release a new `postgres_*.py` repository is added -- nothing else needs to
# change for autogenerate to see it.
_REPOSITORY_MODULE_NAMES: tuple[str, ...] = (
    "src.adapter.repository.postgres_artifact",
    "src.adapter.repository.postgres_asset",
    "src.adapter.repository.postgres_audit_log",
    "src.adapter.repository.postgres_case",
    "src.adapter.repository.postgres_dead_letter",
    "src.adapter.repository.postgres_detection",
    "src.adapter.repository.postgres_detection_correlation",
    "src.adapter.repository.postgres_evidence",
    "src.adapter.repository.postgres_ioc_feed",
    "src.adapter.repository.postgres_quota",
    "src.adapter.repository.postgres_rule_pack",
    "src.adapter.repository.postgres_sealed_batch",
    "src.adapter.repository.postgres_source_cursor",
    "src.adapter.repository.postgres_yara_rule_pack",
)


def build_target_metadata() -> sa.MetaData:
    """Import every repository module and copy its tables into one MetaData."""
    import importlib

    combined = sa.MetaData()
    seen_table_names: set[str] = set()
    for module_name in _REPOSITORY_MODULE_NAMES:
        module: ModuleType = importlib.import_module(module_name)
        module_metadata: sa.MetaData = module._metadata  # type: ignore[attr-defined]
        for table in module_metadata.tables.values():
            if table.name in seen_table_names:
                raise RuntimeError(
                    f"Duplicate table name '{table.name}' across repository modules -- "
                    "each postgres_*.py module must define uniquely-named tables."
                )
            seen_table_names.add(table.name)
            table.tometadata(combined)
    return combined
