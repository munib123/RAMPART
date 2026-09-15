"""asyncpg database module: a lazily-created connection pool plus tiny helpers so
routers never juggle connections directly. Degrades gracefully when DATABASE_URL is
unset (the app still runs; persistence endpoints return a clear error)."""
from __future__ import annotations

import asyncio

from app import config

_pool = None
_lock = asyncio.Lock()


def enabled() -> bool:
    return bool(config.DATABASE_URL)


async def get_pool():
    global _pool
    async with _lock:
        if _pool is None:
            if not config.DATABASE_URL:
                raise RuntimeError("DATABASE_URL is not set in .env")
            _pool = await asyncpg_create()
        return _pool


async def _init_conn(conn):
    # jsonb columns (scans.counts/scope/joern, findings.exemplar_urls) come back as Python
    # objects instead of JSON text, so a history row's counts are usable as-is by the UI.
    # Encoding stays tolerant: routers pass json.dumps(...) strings today; dicts also work.
    import json
    enc = lambda v: v if isinstance(v, str) else json.dumps(v)
    for t in ("json", "jsonb"):
        await conn.set_type_codec(t, encoder=enc, decoder=json.loads, schema="pg_catalog")


async def asyncpg_create():
    import asyncpg
    return await asyncpg.create_pool(config.DATABASE_URL, min_size=1, max_size=5, init=_init_conn)


async def fetch_all(query: str, *args):
    pool = await get_pool()
    async with pool.acquire() as conn:
        return [dict(r) for r in await conn.fetch(query, *args)]


async def fetch_row(query: str, *args):
    pool = await get_pool()
    async with pool.acquire() as conn:
        r = await conn.fetchrow(query, *args)
        return dict(r) if r else None


async def fetch_val(query: str, *args):
    pool = await get_pool()
    async with pool.acquire() as conn:
        return await conn.fetchval(query, *args)


async def execute(query: str, *args):
    pool = await get_pool()
    async with pool.acquire() as conn:
        return await conn.execute(query, *args)


async def close():
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


# --------------------------------------------------------------------------- #
# migrations: backend/db/schema.sql is 0001; backend/db/migrations/NNNN_*.sql bring an
# existing database forward. Applied files are recorded in schema_migrations so each runs
# once; the files are written to be idempotent anyway (add column if not exists ...).
# --------------------------------------------------------------------------- #

from pathlib import Path as _Path

DB_DIR = _Path(__file__).resolve().parent.parent / "db"
SCHEMA = DB_DIR / "schema.sql"
MIGRATIONS = DB_DIR / "migrations"
BASE = "0001_schema"


def migration_files() -> list[_Path]:
    if not MIGRATIONS.is_dir():
        return []
    return sorted(p for p in MIGRATIONS.glob("[0-9][0-9][0-9][0-9]_*.sql"))


def pending(available: list[str], applied: set[str]) -> list[str]:
    """Names still to run, in file order. Pure, so it is testable without a database."""
    return [n for n in sorted(available) if n not in applied]


async def migrate(log=print) -> list[str]:
    """Bring the database up to date. Returns the names applied this call (possibly empty).
    Best-effort at start-up: raises only if DATABASE_URL is unset."""
    pool = await get_pool()
    applied_now: list[str] = []
    async with pool.acquire() as conn:
        await conn.execute(
            "create table if not exists schema_migrations ("
            " name text primary key, applied_at timestamptz not null default now())")
        applied = {r["name"] for r in await conn.fetch("select name from schema_migrations")}

        # 0001: a fresh database gets schema.sql; an existing one (tables present, created by
        # hand from schema.sql before this runner existed) is recorded as already at 0001.
        if BASE not in applied:
            has_users = await conn.fetchval(
                "select exists (select 1 from pg_tables where schemaname='public' and tablename='users')")
            if not has_users:
                async with conn.transaction():
                    await conn.execute(SCHEMA.read_text(encoding="utf-8"))
                applied_now.append(BASE)
            await conn.execute(
                "insert into schema_migrations (name) values ($1) on conflict do nothing", BASE)
            applied.add(BASE)

        files = {p.stem: p for p in migration_files()}
        for name in pending(list(files), applied):
            async with conn.transaction():
                await conn.execute(files[name].read_text(encoding="utf-8"))
                await conn.execute(
                    "insert into schema_migrations (name) values ($1) on conflict do nothing", name)
            applied_now.append(name)
    if applied_now:
        log(f"[db] applied migrations: {', '.join(applied_now)}")
    return applied_now


def _main() -> int:
    """`python -m app.db` from backend/: apply pending migrations and print what happened."""
    if not enabled():
        print("DATABASE_URL is not set in .env")
        return 1

    async def run():
        applied = await migrate()
        print("[db] up to date" if not applied else f"[db] applied {len(applied)} migration(s)")
        await close()

    asyncio.run(run())
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_main())
