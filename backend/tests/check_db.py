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

    await conn.close()
    print("ALL CHECKS PASSED")
    return 0


async def asyncpg_connect():
    import asyncpg
    return await asyncpg.connect(config.DATABASE_URL)


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))