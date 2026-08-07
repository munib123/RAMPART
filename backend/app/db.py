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


async def asyncpg_create():
    import asyncpg
    return await asyncpg.create_pool(config.DATABASE_URL, min_size=1, max_size=5)


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