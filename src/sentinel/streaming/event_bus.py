# SPDX-License-Identifier: Apache-2.0
"""Event bus for SENTINEL streaming."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Event:
    """Event in the streaming system."""

    topic: str
    key: str
    value: dict[str, Any]
    timestamp: float
    partition: int = 0
    offset: int = 0


class EventBus(ABC):
    """Event bus protocol for streaming."""

    @abstractmethod
    async def publish(self, topic: str, event: Event) -> None:
        """Publish an event to a topic."""

    @abstractmethod
    async def subscribe(
        self,
        topic: str,
        group_id: str,
        callback: Any,
    ) -> None:
        """Subscribe to a topic."""

    @abstractmethod
    async def start(self) -> None:
        """Start the event bus."""

    @abstractmethod
    async def stop(self) -> None:
        """Stop the event bus."""

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the event bus is healthy."""


@dataclass
class InProcessBus(EventBus):
    """In-process event bus for appliance mode."""

    _topics: dict[str, list[Event]] = field(default_factory=dict)
    _subscribers: dict[str, list[Any]] = field(default_factory=dict)
    _running: bool = False

    async def publish(self, topic: str, event: Event) -> None:
        """Publish an event to a topic."""
        if topic not in self._topics:
            self._topics[topic] = []
        self._topics[topic].append(event)

        # Notify subscribers
        for callback in self._subscribers.get(topic, []):
            await callback(event)

    async def subscribe(
        self,
        topic: str,
        group_id: str,
        callback: Any,
    ) -> None:
        """Subscribe to a topic."""
        if topic not in self._subscribers:
            self._subscribers[topic] = []
        self._subscribers[topic].append(callback)

    async def start(self) -> None:
        """Start the event bus."""
        self._running = True

    async def stop(self) -> None:
        """Stop the event bus."""
        self._running = False

    async def health_check(self) -> bool:
        """Check if the event bus is healthy."""
        return self._running

    def get_events(self, topic: str) -> list[Event]:
        """Get all events for a topic (for testing)."""
        return self._topics.get(topic, [])
