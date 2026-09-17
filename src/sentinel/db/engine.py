# SPDX-License-Identifier: Apache-2.0
"""Database engine factory for SENTINEL.

Provides async SQLAlchemy engine and session factory.
In appliance mode, uses SQLite. In platform mode, uses PostgreSQL + TimescaleDB.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

logger = logging.getLogger(__name__)


def create_engine(
    database_url: str = "sqlite+aiosqlite:///sentinel.db",
    echo: bool = False,
    pool_size: int = 5,
    max_overflow: int = 10,
) -> AsyncEngine:
    """Create an async SQLAlchemy engine.

    Args:
        database_url: Database connection URL.
        echo: Whether to echo SQL statements.
        pool_size: Connection pool size.
        max_overflow: Maximum overflow connections.

    Returns:
        AsyncEngine instance.
    """
    kwargs: dict[str, int | bool] = {"echo": echo}

    if "sqlite" not in database_url:
        kwargs["pool_size"] = pool_size
        kwargs["max_overflow"] = max_overflow

    engine = create_async_engine(database_url, **kwargs)
    logger.info("Created engine for %s", database_url.split("@")[-1])
    return engine


def create_session_factory(
    engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    """Create a session factory bound to an engine."""
    return async_sessionmaker(engine, expire_on_commit=False)


async def get_session(
    factory: async_sessionmaker[AsyncSession],
) -> AsyncGenerator[AsyncSession, None]:
    """Get a database session from the factory."""
    async with factory() as session:
        yield session
