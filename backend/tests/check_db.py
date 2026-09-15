"""Verify the Supabase connection + schema. Run from backend/:
    .venv\\Scripts\\python.exe tests\\check_db.py
Exits non-zero on failure."""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import config
import app.db as db


async def main():
    if not config.DATABASE_URL:
        print("FAIL: DATABASE_URL is not set in .env")
        return 1
    if not config.JWT_SECRET:
        print("WARN: JWT_SECRET not set (auth will be disabled)")

    conn = await asyncpg_connect()
    tables = await conn.fetch(
        "select tablename from pg_tables where schemaname='public' order by tablename"
    )
    views = await conn.fetch(
        "select viewname from pg_views where schemaname='public' order by viewname"
    )
    names = [r["tablename"] for r in tables]
    print("CONNECT OK")
    print("tables:", ", ".join(names) or "(none)")
    print("views: ", ", ".join(v["viewname"] for v in views) or "(none)")

    required = {"users", "scans", "findings"}
    missing = required - set(names)
    if missing:
        print(f"FAIL: missing tables: {missing}")
        await conn.close()
        return 1

    for t in sorted(required):
        n = await conn.fetchval(f"select count(*) from {t}")
        print(f"  {t}: {n} row(s)")

    view = [v["viewname"] for v in views if v["viewname"] == "cwe_stats"]
    print("cwe_stats view:", "present" if view else "MISSING")
    if "cwe_stats" not in view:
        await conn.close()
        return 1

    # P4 provenance (backend/db/migrations/0002_joern.sql): applied automatically at backend
    # start-up, or by `python -m app.db`. Report rather than fail if it has not run yet.
    cols = {(r["table_name"], r["column_name"]) for r in await conn.fetch(
        "select table_name, column_name from information_schema.columns "
        "where table_schema='public' and table_name in ('findings','scans')")}
    p4 = {("findings", "tool"), ("scans", "joern")}
    have = p4 <= cols and any(v["viewname"] == "tool_stats" for v in views)
    applied = [r["name"] for r in await conn.fetch(
        "select name from schema_migrations order by name")] if "schema_migrations" in names else []
    print("migrations:", ", ".join(applied) or "(schema_migrations table absent)")
    print("0002_joern (findings.tool, scans.joern, tool_stats):",
          "present" if have else "NOT APPLIED - start the backend once or run: python -m app.db")
    if have:
        by_tool = await conn.fetch("select tool, count(*) n from findings group by tool order by n desc")
        print("  findings by tool:", ", ".join(f'{r["tool"]}={r["n"]}' for r in by_tool) or "(none)")

    await conn.close()
    print("ALL CHECKS PASSED")
    return 0


async def asyncpg_connect():
    import asyncpg
    return await asyncpg.connect(config.DATABASE_URL)


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))