# emulator/core/event_bus.py
from typing import Callable, Dict, List, Any, Union

class EventBus:
    """
    A dynamic, user-configurable event bus.
    Components can subscribe to named events (strings or Enum members) and publish payloads.
    """
    def __init__(self):
        # mapping: event key -> list of (priority, handler)
        self._subscribers: Dict[Any, List[tuple[int, Callable[..., Any]]]] = {}

    def subscribe(self, event: Any, handler: Callable[..., Any], priority: int = 0) -> None:
        """
        Subscribe a handler to an event with optional priority.
        Higher priority handlers run first.
        """
        subs = self._subscribers.setdefault(event, [])
        subs.append((priority, handler))
        # keep subscribers sorted by descending priority
        subs.sort(key=lambda x: -x[0])

    def unsubscribe(self, event: Any, handler: Callable[..., Any]) -> None:
        """
        Remove a handler from an event.
        """
        if event in self._subscribers:
            subs = [s for s in self._subscribers[event] if s[1] is not handler]
            if subs:
                self._subscribers[event] = subs
            else:
                del self._subscribers[event]

    def publish(self, event: Any, *args, **kwargs) -> List[Any]:
        """
        Publish an event, invoking all handlers in order of priority.
        Handlers may return values; returns list of results.
        """
        results: List[Any] = []
        for _, handler in self._subscribers.get(event, []):
            try:
                results.append(handler(*args, **kwargs))
            except Exception as e:
                results.append(e)
        return results

    def subscribed_events(self) -> List[Any]:
        """
        Returns the list of event keys with at least one subscriber.
        """
        return list(self._subscribers.keys())
