from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import asyncpg


class PoolManager:
    def __init__(self, dsn: str) -> None:
        self.dsn = dsn
        self.pool: asyncpg.Pool | None = None

    async def connect(self) -> None:
        if self.pool is None:
            self.pool = await asyncpg.create_pool(self.dsn, min_size=1, max_size=5)

    async def close(self) -> None:
        if self.pool is not None:
            await self.pool.close()
            self.pool = None

    @asynccontextmanager
    async def connection(self) -> AsyncIterator[asyncpg.Connection]:
        if self.pool is None:
            await self.connect()
        assert self.pool is not None
        async with self.pool.acquire() as connection:
            yield connection
