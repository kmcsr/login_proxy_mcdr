
import traceback
import threading
from typing import Type, Callable

from .utils import *

__all__ = [
	'Event', 'EventEmitter',
]

class Event:
	__slots__ = ('_cancelable', '_canceled', '_request_unregist')

	def __init__(self, *, cancelable: bool = False):
		self._cancelable = cancelable
		self._canceled = False
		self._request_unregist = False

	@property
	def cancelable(self) -> bool:
		return self._cancelable

	@property
	def canceled(self) -> bool:
		return self._canceled

	def cancel(self) -> None:
		if self.cancelable:
			self._canceled = True

	def unregister(self) -> None:
		self._request_unregist = True

	def _on_before_callback(self) -> None:
		pass

class Listener[T: Event]:
	__slots__ = ('callback', 'priority')

	def __init__(self, callback: Callable[[T], None], priority: int | None = None):
		if priority is None:
			priority = 1000
		self.callback = callback
		self.priority = priority

def insert_event_listener[T: Event](listener: Listener[T], lst: list[Listener[T]]) -> int:
	if len(lst) == 0:
		lst.append(listener)
		return 0
	l, r = 0, len(lst) - 1
	m: int = 0
	while l <= r:
		m = (l + r) // 2
		o = lst[m].priority
		if o == listener.priority:
			if m + 1 == len(lst) or lst[m + 1] != listener.priority:
				lst.insert(m + 1, listener)
				return m + 1
		if o > listener.priority:
			r = m - 1
		else:
			l = m + 1
	if lst[m].priority >= listener.priority:
		lst.insert(m + 1, listener)
		return m + 1
	lst.insert(m, listener)
	return m

class EventEmitter[T: Event]:
	def __init__(self) -> None:
		self._listeners: dict[int, list[Listener[T]]] = {}

	def emit(self, event_id: int, event: T) -> None:
		listeners = self._listeners.get(event_id, [])
		for i, l in list(enumerate(listeners)):
			event._request_unregist = False
			event._on_before_callback()
			l.callback(event)
			if event._request_unregist:
				listeners.remove(l)
			if event.cancelable and event.canceled:
				break

	def register(self, event_id: int, callback: Callable[[T], None], priority: int | None = None) -> None:
		l = Listener(callback, priority)
		if event_id not in self._listeners:
			self._listeners[event_id] = []
		insert_event_listener(l, self._listeners[event_id])
		debug(f'Registered listener {callback} (priority={l.priority}) for {event_id}')

	def unregister(self, event_id: int, callback: Callable[[T], None] | None = None) -> bool:
		if event_id not in self._listeners:
			return False
		if callback is None:
			return len(self._listeners.pop(event_id)) > 0
		listeners = self._listeners[event_id]
		for i, l in enumerate(listeners):
			if l.callback == callback:
				listeners.pop(i)
				return True
		return False
