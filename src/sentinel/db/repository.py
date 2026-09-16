# SPDX-License-Identifier: Apache-2.0
"""Repository layer for SENTINEL.

Repositories return Pydantic contracts, not ORM objects.
The domain layer never depends on the database.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Generic, TypeVar
from uuid import UUID

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


class Repository(ABC, Generic[T]):
    """Repository protocol for aggregates."""

    @abstractmethod
    async def get(self, id: UUID) -> T | None:
        """Get an entity by ID."""

    @abstractmethod
    async def list(
        self,
        filters: dict[str, Any] | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> list[T]:
        """List entities with optional filters."""

    @abstractmethod
    async def create(self, entity: T) -> T:
        """Create a new entity."""

    @abstractmethod
    async def update(self, id: UUID, entity: T) -> T | None:
        """Update an existing entity."""

    @abstractmethod
    async def delete(self, id: UUID) -> bool:
        """Delete an entity."""

    @abstractmethod
    async def count(self, filters: dict[str, Any] | None = None) -> int:
        """Count entities with optional filters."""


class InMemoryRepository(Repository[T]):
    """In-memory repository for testing."""

    def __init__(self) -> None:
        self._store: dict[UUID, T] = {}

    async def get(self, id: UUID) -> T | None:
        return self._store.get(id)

    async def list(
        self,
        filters: dict[str, Any] | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> list[T]:
        items = list(self._store.values())
        return items[offset : offset + limit]

    async def create(self, entity: T) -> T:
        self._store[entity.id] = entity  # type: ignore
        return entity

    async def update(self, id: UUID, entity: T) -> T | None:
        if id in self._store:
            self._store[id] = entity
            return entity
        return None

    async def delete(self, id: UUID) -> bool:
        if id in self._store:
            del self._store[id]
            return True
        return False

    async def count(self, filters: dict[str, Any] | None = None) -> int:
        return len(self._store)
