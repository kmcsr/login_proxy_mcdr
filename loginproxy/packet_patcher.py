# This package apply fixes for proxied data packets in specific minecraft versions

import time
import uuid
from typing import Callable

try:
	import packet_parser
except ImportError:
	raise ImportError('packet_parser plugin required')

from .server import *
from .protocols import Protocol
from .utils import *

__all__ = [
	'patch_connection',
]

patchers: dict[int, Callable[[Conn], None]] = {}

def patch_connection(conn: Conn):
	patcher = patchers.get(conn.protocol, None)
	if patcher is not None:
		debug(f'applying patcher {patcher} for {conn}')
		patcher(conn)

#### VERSIONS ####

def patch_v1_21_1(conn: Conn):
	conn.register_packet('play_player_session', patch_play_player_session, priority=-100)

patchers[Protocol.V1_21_1] = patch_v1_21_1

#### PACKETS ####

class PlayerSession:
	def __init__(self, session_id: uuid.UUID, expires_at: float, public_key: bytes):
		self.id = session_id
		self.expires_at = expires_at
		self.public_key = public_key

def patch_play_player_session(event: PacketEvent):
	event.cancel()

	packet = event.reader
	session_id = packet.read_uuid()
	expires_at = packet.read_long() / 1000
	public_key = packet.read_bytearray()
	key_signature = packet.read_bytearray()

	if expires_at < time.time():
		event.conn.kick('public key expired')
		return
	# TODO: verify signature

	debug('session_id:', session_id)
	debug('public_key:', repr(public_key))
	event.conn._custom_data['player_session'] = PlayerSession(session_id, expires_at, public_key)

