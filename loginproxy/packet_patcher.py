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

patchers: list[tuple[int, Callable[[Conn], None]]] = []

def patch_connection(conn: Conn):
	for v, patcher in patchers:
		if conn.protocol >= v:
			debug(f'applying patcher ({v} < {conn.protocol}) {patcher} for {conn}')
			patcher(conn)

#### VERSIONS ####

def patch_v1_20_1(conn: Conn):
	conn.register_packet('play_player_info_update', patch_play_player_info_update, priority=-100)
	conn.register_packet('play_player_session', patch_play_player_session, priority=-100)

patchers.append((Protocol.V1_20_1, patch_v1_20_1))

#### PACKETS ####

class ChatSession:
	def __init__(self, session_id: uuid.UUID, public_key: bytes):
		self.id = session_id
		self.public_key = public_key

def patch_play_player_info_update(event: PacketEvent):
	conn = event.conn
	packet = event.reader
	action = packet.read_byte()
	if action != 0x02:
		return
	event.cancel()

def patch_play_player_session(event: PacketEvent):
	event.cancel()

	conn = event.conn
	packet = event.reader
	session_id = packet.read_uuid()
	expires_at = packet.read_long()
	public_key = packet.read_bytearray()
	key_signature = packet.read_bytearray()

	if expires_at < time.time() * 1000:
		conn.kick({
			'translate': 'multiplayer.disconnect.expired_public_key',
		})
		return
	# TODO: verify signature
	if False:
		conn.kick({
			'translate': 'multiplayer.disconnect.invalid_public_key_signature.new'
		})

	debug('session_id:', session_id)
	debug('public_key:', repr(public_key))
	conn._custom_data['player_session'] = ChatSession(session_id, public_key)
	conn.new_packet('play_player_info_update').\
		write_byte(0x02).\
		write_varint(1).\
		write_uuid(conn._custom_data['uuid']).\
		write_bool(True).\
		write_uuid(session_id).\
		write_long(expires_at).\
		write_bytearray(public_key).\
		write_bytearray(key_signature).\
		broadcast()
