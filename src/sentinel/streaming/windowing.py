# SPDX-License-Identifier: Apache-2.0
"""Event-time windowing with watermarks."""

from __future__ import annotations

from dataclasses import dataclass, field

from sentinel.schemas import UnifiedEvent


@dataclass
class Window:
    """Time window for event aggregation."""

    start: float
    end: float
    events: list[UnifiedEvent] = field(default_factory=list)
    closed: bool = False


@dataclass
class Watermark:
    """Watermark for tracking event-time progress."""

    current: float
    lateness: float = 30.0  # Default 30 seconds allowed lateness

    def advance(self, event_time: float) -> None:
        """Advance watermark based on event time."""
        self.current = max(self.current, event_time)

    def is_window_closed(self, window_end: float) -> bool:
        """Check if a window should be closed."""
        return self.current >= window_end + self.lateness


class EventTimeWindower:
    """Event-time windowing with watermarks.

    Handles late arrivals and out-of-order events.
    """

    def __init__(
        self,
        window_size: float,
        window_stride: float,
        lateness: float = 30.0,
    ) -> None:
        """Initialize windower.

        Args:
            window_size: Window duration in seconds.
            window_stride: Window stride in seconds.
            lateness: Allowed lateness in seconds.
        """
        self.window_size = window_size
        self.window_stride = window_stride
        self.watermark = Watermark(current=0.0, lateness=lateness)
        self.windows: dict[float, Window] = {}
        self.late_events: list[UnifiedEvent] = []

    def process_event(self, event: UnifiedEvent) -> list[Window]:
        """Process an event and return any closed windows.

        Args:
            event: The event to process.

        Returns:
            List of windows that were closed by this event.
        """
        event_time = event.timestamp.timestamp()
        self.watermark.advance(event_time)

        # Find or create window for this event
        window_start = self._get_window_start(event_time)
        if window_start not in self.windows:
            self.windows[window_start] = Window(
                start=window_start,
                end=window_start + self.window_size,
            )

        # Add event to window
        self.windows[window_start].events.append(event)

        # Check for closed windows
        closed_windows = []
        for _ws, window in list(self.windows.items()):
            if not window.closed and self.watermark.is_window_closed(window.end):
                window.closed = True
                closed_windows.append(window)

        return closed_windows

    def get_late_events(self) -> list[UnifiedEvent]:
        """Get events that arrived after their window closed."""
        late = self.late_events
        self.late_events = []
        return late

    def _get_window_start(self, timestamp: float) -> float:
        """Get the window start time for a timestamp."""
        return (timestamp // self.window_stride) * self.window_stride
