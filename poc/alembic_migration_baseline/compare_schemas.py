import asyncio
import os
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

def reflect_sync(sync_conn):
    insp = sa.inspect(sync_conn)
    result = {}
    for table_name in sorted(insp.get_table_names()):
        if table_name == "alembic_version":
            continue
        cols = []
        for c in insp.get_columns(table_name):
            cols.append((
                c["name"],
                str(c["type"]).upper(),
                c["nullable"],
                str(c.get("default")),
            ))
        pk = insp.get_pk_constraint(table_name)
        uniques = sorted(
            (u["name"], tuple(sorted(u["column_names"]))) for u in insp.get_unique_constraints(table_name)
        )
        indexes = sorted(
            (ix["name"], tuple(sorted(ix["column_names"])), ix["unique"])
            for ix in insp.get_indexes(table_name)
        )
        result[table_name] = {
            "columns": sorted(cols),
            "pk": sorted(pk.get("constrained_columns") or []),
            "unique": uniques,
            "indexes": indexes,
        }
    return result

async def reflect(url):
    engine = create_async_engine(url, poolclass=sa.pool.NullPool)
    async with engine.connect() as conn:
        data = await conn.run_sync(reflect_sync)
    await engine.dispose()
    return data

async def main():
    alembic_url = os.environ["ALEMBIC_DB_URL"]
    createall_url = os.environ["CREATEALL_DB_URL"]
    a = await reflect(alembic_url)
    c = await reflect(createall_url)

    a_tables = set(a.keys())
    c_tables = set(c.keys())
    print(f"Alembic-produced tables: {len(a_tables)}")
    print(f"create_tables()-produced tables: {len(c_tables)}")
    only_in_a = a_tables - c_tables
    only_in_c = c_tables - a_tables
    if only_in_a:
        print("TABLES ONLY IN ALEMBIC:", sorted(only_in_a))
    if only_in_c:
        print("TABLES ONLY IN CREATE_TABLES:", sorted(only_in_c))

    mismatches = 0
    for table in sorted(a_tables & c_tables):
        if a[table] != c[table]:
            mismatches += 1
            print(f"--- MISMATCH: {table} ---")
            if a[table]["columns"] != c[table]["columns"]:
                print("  alembic columns:   ", a[table]["columns"])
                print("  createall columns: ", c[table]["columns"])
            if a[table]["pk"] != c[table]["pk"]:
                print("  alembic pk:  ", a[table]["pk"])
                print("  createall pk:", c[table]["pk"])
            if a[table]["unique"] != c[table]["unique"]:
                print("  alembic unique:  ", a[table]["unique"])
                print("  createall unique:", c[table]["unique"])
            if a[table]["indexes"] != c[table]["indexes"]:
                print("  alembic indexes:  ", a[table]["indexes"])
                print("  createall indexes:", c[table]["indexes"])

    print(f"\nTotal tables compared: {len(a_tables & c_tables)}")
    print(f"Mismatches: {mismatches}")
    if not only_in_a and not only_in_c and mismatches == 0:
        print("RESULT: SCHEMAS ARE IDENTICAL (modulo alembic_version bookkeeping table)")
    else:
        print("RESULT: SCHEMAS DIFFER")

asyncio.run(main())
