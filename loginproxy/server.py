
import abc
import enum
import functools
import hashlib
import ipaddress
import os
import socket
import threading
import time
import traceback
import uuid
import zlib
from abc import abstractmethod
from math import *
from typing import final, Any, Self, Callable

import mcdreforged.api.all as MCDR

from kpi.config import Properties
from .configs import *
from .constants import *
from .encoder import *
from .encryptor import *
from .event import *
from .utils import *
from . import mojang

__all__ = [
	'PacketEvent',
	'ConnStatus', 'Conn',
	'ProxyServer',
]

DEBUG_PACKET = False

class ConnStatus(int, enum.Enum):
	HANDSHAKING   = 0
	STATUS        = 1
	LOGIN         = 2
	CONFIGURATION = 3
	PLAY          = 4

	@classmethod
	def from_packet_name(cls, name: str) -> Self:
		status = name.split('_', 1)[0].upper()
		return getattr(cls, status)

class PacketEvent(Event):
	__slots__ = ('_conn', '_reader', '_is_client')

	def __init__(self, conn: 'Conn', reader: PacketReader, *, is_client: bool):
		super().__init__(cancelable=True)
		self._conn = conn
		self._reader = reader
		self._is_client = is_client

	@property
	def conn(self) -> 'Conn':
		return self._conn

	@property
	def reader(self) -> PacketReader:
		return self._reader

	@property
	def protocol(self) -> int:
		return self._conn.protocol

	@property
	def player(self) -> str:
		return self._conn.name

	@property
	def id(self) -> int:
		return self._reader.id

	@property
	def data(self) -> bytes:
		return self._reader.data[self._reader._read_id:]

	@property
	def is_client(self) -> bool:
		return self._is_client

	@property
	def is_server(self) -> bool:
		return not self._is_client

	def _on_before_callback(self) -> None:
		self._reader.reset()

class Conn(EventEmitter[PacketEvent]):
	def __init__(self, name: str, addr: tuple[str, int],
		server: 'ProxyServer',
		conn_client: socket.socket, conn_server: socket.socket,
		login_data: dict):
		super().__init__()
		self._name = name
		self._addr = addr
		self._conn_client = conn_client
		self._conn_server = conn_server
		self._wrapped_conn_client: IConnection = conn_client
		self._wrapped_conn_server: IConnection = conn_server
		self._client_send_lock = threading.Lock()
		self._server_send_lock = threading.Lock()
		self._login_data = login_data
		self._protocol = login_data['protocol']
		self._client_status = ConnStatus.HANDSHAKING
		self._server_status = ConnStatus.HANDSHAKING
		self._client_compress_threshold = -1
		self._server_compress_threshold = -1
		self._secrect: bytes | None = None
		self._server = server
		self._streaming = False
		self._alive = True
		self._kicking = None
		self._custom_data: dict = {}

	@property
	def name(self) -> str:
		return self._name

	@property
	def addr(self) -> tuple[str, int]:
		return self._addr

	@property
	def ip(self) -> str:
		return self._addr[0]

	@property
	def conn_client(self):
		return self._conn_client

	@property
	def conn_server(self):
		return self._conn_server

	@property
	def login_data(self) -> dict:
		return self._login_data

	@property
	def protocol(self) -> int:
		return self._protocol

	@property
	def client_status(self) -> ConnStatus:
		return self._client_status

	@property
	def server_status(self) -> ConnStatus:
		return self._server_status

	def _recvpkt(self, conn: IConnection, *, compress_threshold_getter, side: str) -> PacketReader:
		leng = recv_varint(conn)
		leng1 = leng
		data_leng, size = 0, 0
		compressed = compress_threshold_getter() >= 0
		if compressed:
			data_leng, size = recv_varint2(conn)
			leng -= size
		data = b''
		while len(data) < leng:
			data += conn.recv(leng - len(data))
		if data_leng > 0:
			try:
				data = zlib.decompress(data)
			except zlib.error as e:
				debug(f'Incorrect compressed data: {repr(data)}')
				raise
		packet = PacketReader(data)
		if DEBUG_PACKET:
			debug(f'Received packet; leng={leng + size}; compressed={compressed}; data_leng={data_leng}; id={hex(packet.id)} from {side}')
		return packet

	def recv_client(self) -> PacketReader:
		"""
		Recv packet from the client
		"""
		return self._recvpkt(self._wrapped_conn_client, compress_threshold_getter=lambda: self._client_compress_threshold, side='client')

	def recv_server(self) -> PacketReader:
		"""
		Recv packet from the server
		"""
		return self._recvpkt(self._wrapped_conn_server, compress_threshold_getter=lambda: self._server_compress_threshold, side='server')

	def _sendpkt(self, conn: IConnection, data: bytes, *, lock: threading.Lock, compress_threshold: int, side: str):
		data_leng = 0
		did = data[0]
		if compress_threshold >= 0:
			if len(data) > compress_threshold:
				data_leng = len(data)
				data = zlib.compress(data)
			data = encode_varint(data_leng) + data
		with lock:
			if DEBUG_PACKET:
				debug(f'Sending packet; leng={len(data)}; compressed={compress_threshold >= 0}; data_leng={data_leng}; id={hex(did)}; to {side}')
			conn.sendall(encode_varint(len(data)) + data)

	def send_client(self, data: bytes):
		"""
		Send packet to the client
		"""
		self._sendpkt(self._wrapped_conn_client, data, lock=self._client_send_lock, compress_threshold=self._client_compress_threshold, side='client')

	def send_server(self, data: bytes):
		"""
		Send packet to the server
		"""
		self._sendpkt(self._wrapped_conn_server, data, lock=self._server_send_lock, compress_threshold=self._server_compress_threshold, side='server')

	@property
	def server(self) -> 'ProxyServer':
		return self._server

	@property
	def isalive(self) -> bool:
		return self._alive

	def _get_disconnect_packet_id(self) -> int:
		if self.client_status == ConnStatus.LOGIN:
			return 0x00
		elif self.client_status == ConnStatus.PLAY:
			return Protocol.get_disconnect_play_id(self.protocol)
		elif self.client_status == ConnStatus.CONFIGURATION:
			return 0x02
		raise ValueError(f'Unexpect client status {self.client_status}')

	def kick(self, reason: str | dict[str, Any] = 'You have been kicked', *,
		server: MCDR.ServerInterface | None = None) -> bool:
		if not self.isalive:
			return False
		debug(f'kicking client {self.name}{self.addr}: {reason}')
		if not self._streaming:
			disconnect_id = self._get_disconnect_packet_id()
			if self.protocol >= Protocol.V1_20_4 and self.client_status != ConnStatus.LOGIN:
				from packet_parser import nbt
				buf = PacketBuffer()
				buf.write_varint(disconnect_id)
				if isinstance(reason, str):
					nbt.String('LoginProxy: ' + reason).to_bytes(buf)
				else:
					nbt.chat_object_to_nbt(reason).to_bytes(buf)
				debug('Disconnected:', buf.data)
				self.send_client(buf.data)
			else:
				if isinstance(reason, str):
					reason = {
						'text': 'LoginProxy: ' + reason,
					}
				self.send_client(encode_varint(disconnect_id) + encode_json(reason))
			self._alive = False
			self.conn_server.close()
			time.sleep(0.5)
			self.conn_client.close()
			self.server._pop_uconn(self.conn_client)
			return True
		if self._kicking is not None:
			return False
		if server is None:
			server = self.server.config.server
		if self.server.config.kick_cmd is not None and len(self.server.config.kick_cmd) > 0:
			server.execute(self.server.config.kick_cmd.format(name=self.name, reason=reason))
			self._kicking = new_timer(5.0, self.disconnect, name='lp_defer_close')
		else:
			self.disconnect()
		return True

	def disconnect(self) -> None:
		log_info('Force disconnecting player {0}[{1[0]}:{1[1]}]'.format(self.name, self.addr))
		if self._kicking is not None:
			self._kicking.cancel()
			self._kicking = None
		self.conn_client.close()
		self.conn_server.close()
		self.server._pop_uconn(self.conn_client)
		self._alive = False

	def emit_packet(self, event: PacketEvent) -> None:
		self.emit(-2 if event.is_client else -1, event)
		if event.canceled:
			return
		self.emit(event.id, event)

	def get_idset(self):
		from packet_parser import PacketIdSet
		return PacketIdSet.from_protocol(self.protocol)

	def register_s2c(self, callback: Callable[[PacketEvent], None], priority: int | None = None) -> None:
		self.register(-1, callback, priority)

	def register_c2s(self, callback: Callable[[PacketEvent], None], priority: int | None = None) -> None:
		self.register(-2, callback, priority)

	def register_packet(self, packet_name: str, callback: Callable[[PacketEvent], None], priority: int | None = None, *,
		slient_fail: bool = False) -> bool:
		idset = self.get_idset()
		packet_id: int | None = getattr(idset, packet_name, None)
		if packet_id is None:
			if slient_fail:
				return False
			raise ValueError(f'{repr(packet_name)} does not exists in protocol {idset.version} (include {self.protocol})')

		is_c2s = idset.is_c2s[packet_name]
		status = ConnStatus.from_packet_name(packet_name)

		if is_c2s:
			@functools.wraps(callback)
			def cb(event: PacketEvent):
				if event.is_client and event.conn.client_status == status:
					callback(event)
		else:
			@functools.wraps(callback)
			def cb(event: PacketEvent):
				if event.is_server and event.conn.server_status == status:
					callback(event)
		self.register(packet_id, cb, priority)
		return True

	def new_packet(self, packet_name: str) -> 'PacketBuilder':
		idset = self.get_idset()
		packet_id: int | None = getattr(idset, packet_name, None)
		if packet_id is None:
			raise ValueError(f'{repr(packet_name)} does not exists in protocol {idset.version} (include {self.protocol})')
		status = ConnStatus.from_packet_name(packet_name)
		return PacketBuilder(self, idset.is_c2s[packet_name], status, packet_id)

class PacketBuilder(PacketBuffer):
	__slots__ = ('_conn', '_status', '_is_c2s')

	def __init__(self, conn: Conn, is_c2s: bool, status: ConnStatus, packet_id: int):
		super().__init__()
		self._conn = conn
		self._status = status
		self._is_c2s = is_c2s
		self.write_varint(packet_id)

	def send(self) -> None:
		if self._is_c2s:
			assert self._status == self._conn.server_status
			self._conn.send_server(self.data)
		else:
			assert self._status == self._conn.client_status
			self._conn.send_client(self.data)

	def broadcast(self) -> None:
		if self._is_c2s:
			assert self._status == self._conn.server_status
			sender = Conn.send_server
		else:
			assert self._status == self._conn.client_status
			sender = Conn.send_client
		for conn in self._conn.server.get_conns():
			try:
				sender(conn, self.data)
			except (ConnectionAbortedError, ConnectionResetError):
				pass

class ProxyServer:
	def __init__(self, server: MCDR.ServerInterface, base: str, config: LPConfig, whlist: ListConfig):
		cls = self.__class__
		self._mcdr_server = server
		self._base = base
		self.__config = config
		self.__whlist = whlist
		self._properties = Properties(os.path.join(self._base, 'server.properties'))
		self._server_addr = (
			self._properties.get_str('server-ip', '127.0.0.1'),
			self._properties.get_int('server-port', 25565))
		if (self.config.proxy_addr.ip is not None and
				self._server_addr[1] == self.config.proxy_addr.port) or \
			(self.config.proxy_addr.ipv6 is not None and
				self._server_addr[1] == self.config.proxy_addr.ipv6_port):
			log_warn(tr('message.warn.port_might_same', self.server_addr, self.config.proxy_addr))
		self._modt = self._properties.get_str('motd', 'A Minecraft Server')
		self._max_players = self._properties.get_int('max-players', 20)

		self._online_mode = self.config.online_mode
		self._enabled_packet_proxy = self.config.enable_packet_proxy
		if self._enabled_packet_proxy:
			from Crypto.Cipher import PKCS1_v1_5
			from Crypto.PublicKey import RSA

			self._private_key = RSA.generate(1024)
			self._cipher = PKCS1_v1_5.new(self._private_key)

		self._on_login = [cls.default_onlogin]
		self._on_ping = [cls.default_onping]
		self._lock = threading.Condition(threading.RLock())
		self.__sockets: list[socket.socket] = []
		self.__status = 0
		self._conns: dict[str, Conn] = {}
		self._uconns: set[socket.socket] = set() # underlying connections

	@property
	def base(self) -> str:
		return self._base

	@property
	def config(self) -> LPConfig:
		return self.__config

	@property
	def whlist(self) -> ListConfig:
		return self.__whlist

	@property
	def properties(self) -> Properties:
		return self._properties

	@property
	def server_addr(self) -> tuple[str, int]:
		return self._server_addr

	@property
	def online_mode(self) -> bool:
		return self._online_mode

	@property
	def modt(self) -> str:
		return self._modt

	@modt.setter
	def modt(self, modt: str):
		self._modt = modt

	@property
	def max_players(self) -> int:
		return self._max_players

	def get_conns(self) -> list[Conn]:
		with self._lock:
			conns = list(self._conns.values())
			return conns

	def get_conn_count(self) -> int:
		return len(self._conns)

	def get_conn(self, name: str) -> Conn | None:
		with self._lock:
			return self._conns.get(name, None)

	def get_conns_by_ip(self, ip: str) -> list[Conn]:
		with self._lock:
			conns = [c for c in self._conns.values() if c.ip == ip]
			return conns

	def get_conns_by_network(self, network) -> list[Conn]:
		assert_instanceof(network, (str, ipaddress.IPv4Network, ipaddress.IPv6Network))
		if isinstance(network, str):
			network = ipaddress.ip_network(network)
		with self._lock:
			conns = [c for c in self._conns.values() if c.ip in network]
			return conns

	def _add_uconn(self, conn: socket.socket):
		with self._lock:
			self._uconns.add(conn)

	def _pop_uconn(self, conn: socket.socket):
		with self._lock:
			self._uconns.discard(conn)

	@property
	def on_login(self):
		return self._on_login

	@on_login.setter
	def on_login(self, callback):
		self._on_login.insert(0, callback)

	@property
	def on_ping(self):
		return self._on_ping

	@on_ping.setter
	def on_ping(self, callback):
		self._on_ping.append(callback)

	@staticmethod
	def default_onlogin(self, conn, addr: tuple[str, int], name: str, login_data: dict):
		if not self._mcdr_server.is_server_startup():
			return False
		log_info('Player {0}[[{1[0]}]:{1[1]}] trying to join'.format(name, addr))
		sokt = self.new_connection(login_data)

		c = Conn(name, addr, self, conn, sokt, login_data)
		c._client_status = ConnStatus.LOGIN
		c._server_status = ConnStatus.LOGIN
		with self._lock:
			if name in self._conns:
				c.kick('Player {} is already exists'.format(name))
				conn.close()
				self._uconns.discard(conn)
				return True
			self._conns[name] = c
		def final():
			with self._lock:
				self._uconns.discard(conn)
				self._conns.pop(c.name, None)
				if c.isalive:
					c.disconnect()
			self._mcdr_server.dispatch_event(ON_LOGOFF, (c, ), on_executor_thread=False)

		canceled = False
		def cancel():
			nonlocal canceled
			canceled = True
		self._mcdr_server.dispatch_event(ON_LOGIN, (c, cancel), on_executor_thread=False)
		if canceled:
			final()
			return True

		if self._enabled_packet_proxy:
			proxy_conn_packet(c, final=final)
		else:
			c._streaming = True
			proxy_conn_stream(conn, sokt, addr, final=final)
		return True

	@staticmethod
	def default_onping(self, conn, addr: tuple[str, int], login_data: dict, status: ServerStatus):
		if get_server_instance().is_server_startup():
			debug('Creating connection for ping...')
			sokt = self.new_connection(login_data)
			debug('Forward ping connection')
			waiter = proxy_conn_stream(conn, sokt, addr, final=lambda: self._pop_uconn(conn))
			waiter()
			debug('Ping connection finished')
			return True
		else:
			debug('Server is not startup yet:', addr)
		return False

	def new_connection(self, login_data: dict):
		sokt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		debug('Connecting to [[{0[0]}]:{0[1]}]...'.format(self.server_addr))
		sokt.connect(self.server_addr)
		protocol = login_data['protocol']
		send_package(sokt, 0x00,
			encode_varint(protocol) +
			encode_string(login_data['host']) +
			encode_short(login_data['port']) +
			encode_varint(login_data['state'])
		)
		if login_data['state'] == 1:
			send_package(sokt, 0x00, b'')
		elif login_data['state'] == 2:
			if protocol >= Protocol.V1_20_2:
				send_package(sokt, 0x00,
					encode_string(login_data['name']) +
					login_data['uuid'].bytes
				)
			elif protocol >= Protocol.V1_19:
				send_package(sokt, 0x00,
					encode_string(login_data['name']) +
					((
						encode_bool(login_data['has_sig']) +
						((encode_long(login_data['timestamp']) +
							encode_varint(len(login_data['pubkey'])) +
							login_data['pubkey'] +
							encode_varint(len(login_data['sign'])) +
							login_data['sign']
						) if login_data['has_sig'] else b'')
					) if protocol <= Protocol.V1_19_2 else b'') +
					((
						encode_bool(login_data['has_uuid']) +
						(login_data['uuid'].bytes if login_data['has_uuid'] else b'')
					) if protocol >= Protocol.V1_19_1 else b'')
				)
			else:
				send_package(sokt, 0x00,
					encode_string(login_data['name'])
				)
		return sokt

	@new_thread
	def __run(self, sock):
		handle = MCDR.new_thread('lp_handler')(self.handle)
		try:
			while self.__status == 1:
				conn, addr = sock.accept()
				if self.__status != 1:
					return
				self._add_uconn(conn)
				handle(conn, addr)
		except (ConnectionAbortedError, OSError):
			pass
		except Exception as e:
			log_error('Error when listening:', str(e))
			traceback.print_exc()
		finally:
			sock.close()
			with self._lock:
				try:
					self.__sockets.remove(sock)
				except ValueError:
					pass
				if len(self.__sockets) == 0:
					self.__status = 0
					self._lock.notify_all()

	@new_thread
	def start(self):
		with self._lock:
			if self.__status != 0:
				log_warn('Proxy server running')
				return
			self.__status = 1
		try:
			ip, port = self.config.proxy_addr.ip, self.config.proxy_addr.port
			ip6, port6 = self.config.proxy_addr.ipv6, self.config.proxy_addr.ipv6_port

			ip = ip if ip or ip is None else '0.0.0.0'
			ip6 = ip6 if ip6 or ip6 is None else '::'

			sock4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			sock4.bind((ip, port))
			sock4.listen(ceil(self.max_players * 3 / 2))
			self.__sockets.append(sock4)
			log_info('Proxy server listening at [{0}]:{1}'.format(ip, port))
			self.__run(sock4)

			if ip6 is not None:
				sock6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
				sock6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
				sock6.bind((ip6, port6))
				sock6.listen(ceil(self.max_players * 3 / 2))
				self.__sockets.append(sock6)
				log_info('Proxy server listening at [{0}]:{1}'.format(ip6, port6))
				self.__run(sock6)
		except:
			with self._lock:
				self.__status = 0
			raise

	def stop(self):
		with self._lock:
			if self.__status != 1:
				debug('stopping with status', self.__status)
				return
			self.__status = 2
			for c in self._conns.values():
				c.kick('MCDR: Login Proxy is stopping')
		for _ in range(30): # wait for 3.0 seconds
			if len(self._conns) == 0:
				break
			time.sleep(0.1)
		else:
			with self._lock:
				for c in self._conns.values():
					c.disconnect()
				self._conns.clear()
		with self._lock:
			for s in self.__sockets:
				try:
					s.shutdown(socket.SHUT_RDWR)
				except OSError: # for WinError 10057
					pass
				s.close()
			self.__sockets.clear()
			for c in self._uconns:
				c.close()
			self._uconns.clear()

	def __del__(self):
		with self._lock:
			for s in self.__sockets:
				try:
					s.shutdown(socket.SHUT_RDWR)
				except OSError: # for WinError 10057
					pass
				s.close()
			for c in self._uconns:
				c.close()

	def handle(self, conn, addr: tuple[str, int]):
		def close_conn():
			conn.close()
			self._pop_uconn(conn)

		try:
			canceled: bool = False
			def cancel():
				nonlocal canceled
				canceled = True
			debug('Client [[{0[0]}]:{0[1]}] connecting'.format(addr))
			get_server_instance().dispatch_event(ON_CONNECT,
				(self, conn, addr, cancel), on_executor_thread=False)
			if canceled:
				debug('Client [[{0[0]}]:{0[1]}] disconnected by event handler'.format(addr))
				close_conn()
				return

			close_flag: bool = True
			pkt = recv_package(conn)
			if pkt.id == 0xfe:
				if conn.recv(2) == b'\x01\xfa':
					debug('Client [[{0[0]}]:{0[1]}] ping with 1.6 format'.format(addr))
					self.handle_ping_1_6(conn, addr)
			elif pkt is None:
				raise RuntimeError('Unexpect packet with none data')
			elif pkt.id == 0x00:
				login_data: dict[str, Any] = {}
				protocol = pkt.read_varint()
				login_data['protocol'] = protocol
				login_data['host'] = pkt.read_string()
				login_data['port'] = pkt.read_ushort()
				state = pkt.read_varint()
				if state == 3: # transfer
					if not self.config.allow_transfer:
						send_package(conn, 0x00, encode_json({
							'translate': 'multiplayer.disconnect.transfers_disabled',
						}))
						return
					state = 2
				login_data['state'] = state
				if state == 1:
					pkt = recv_package(conn)
					if pkt.id == 0x00:
						close_flag = not self.handle_ping_1_7(conn, addr, protocol, login_data)
				elif state == 2:
					pkt = recv_package(conn)
					if pkt.id == 0x00:
						debug('Client [[{0[0]}]:{0[1]}] tring login'.format(addr))
						close_flag = not self.handle_login(conn, addr, login_data, pkt)
		except (ConnectionAbortedError, ConnectionResetError):
			pass
		except Exception as e:
			log_warn('Error when handle[[{0[0]}]:{0[1]}]: {1}'.format(addr, str(e)))
			traceback.print_exc()
		finally:
			if close_flag:
				time.sleep(0.5)
				close_conn()

	def handle_login(self, conn, addr: tuple[str, int], login_data: dict, pkt: PacketReader) -> bool:
		cls = self.__class__

		if self.whlist.is_bannedip(addr[0]):
			debug('Disconnected [[{0[0]}]:{0[1]}] for banned IP'.format(addr))
			send_package(conn, 0x00, encode_json({
				'text': self.config.messages['banned.ip'],
			}))
			return False
		if self.config.enable_ip_whitelist and not self.whlist.is_allowedip(addr[0]):
			debug('Disconnected [[{0[0]}]:{0[1]}] for IP not in whitelist'.format(addr))
			send_package(conn, 0x00, encode_json({
				'text': self.config.messages['whitelist.ip'],
			}))
			return False

		protocol = login_data['protocol']
		if protocol >= Protocol.V1_19:
			cls.login_parser_1_19(pkt, login_data)
		else:
			cls.login_parser_1_8(pkt, login_data)

		name = login_data['name']

		if name in self.whlist.banned:
			debug('Disconnected {1}[[{0[0]}]:{0[1]}] for banned name'.format(addr, name))
			send_package(conn, 0x00, encode_json({
				'text': self.config.messages['banned.name'],
			}))
			return False
		if self.config.enable_whitelist and \
			name not in self.whlist.allowed and \
			self._mcdr_server.get_permission_level(name) < self.config.whitelist_level:
			debug('Disconnected {1}[[{0[0]}]:{0[1]}] for name not in whilelist'.format(addr, name))
			send_package(conn, 0x00, encode_json({
				'text': self.config.messages['whitelist.name'],
			}))
			return False

		canceled: int = 0 # 0: not canceled; 1: handled; 2: disconnected
		def cancel(handled: bool = False):
			nonlocal canceled
			canceled = 1 if handled else 2
		self._mcdr_server.dispatch_event(ON_PRE_LOGIN,
			(self, conn, addr, name, login_data, cancel), on_executor_thread=False)
		if canceled != 0:
			return canceled == 1

		for handle in self._on_login:
			if handle(self, conn, addr, name, login_data):
				return True
		send_package(conn, 0x00, encode_json({
			'text': 'LoginProxy: No login handle found',
		}))
		return False

	@staticmethod
	def login_parser_1_8(pkt: PacketReader, login_data: dict):
		login_data['name'] = pkt.read_string()

	@staticmethod
	def login_parser_1_19(pkt: PacketReader, login_data: dict):
		protocol = login_data['protocol']
		login_data['name'] = pkt.read_string()
		if protocol <= Protocol.V1_19_2:
			has_sig = pkt.read_bool()
			login_data['has_sig'] = has_sig
			if has_sig:
				login_data['timestamp'] = pkt.read_long()
				login_data['pubkey'] = pkt.read(pkt.read_varint())
				login_data['sign'] = pkt.read(pkt.read_varint())
		if protocol >= Protocol.V1_20_2:
			login_data['uuid'] = pkt.read_uuid()
		elif protocol >= Protocol.V1_19_1: # Fix issue #1
			has_uuid = pkt.read_bool()
			login_data['has_uuid'] = has_uuid
			if has_uuid:
				login_data['uuid'] = pkt.read_uuid()

	def handle_ping_1_7(self, conn: socket.socket, addr: tuple[str, int], protocol: int, login_data: dict):
		debug('Client [[{0[0]}]:{0[1]}] ping with 1.7 format'.format(addr))

		if self.whlist.is_bannedip(addr[0]):
			send_package(conn, 0x00, encode_json({
				'text': self.config.messages['banned.ip'],
			}))
			return False
		if self.config.enable_ip_whitelist and not self.whlist.is_allowedip(addr[0]):
			send_package(conn, 0x00, encode_json({
				'text': self.config.messages['whitelist.ip'],
			}))
			return False

		status = ServerStatus('Idle', 0, 1, 0, [], { 'text': self.modt }, None, False)
		self._mcdr_server.dispatch_event(ON_PING,
			(self, conn, addr, login_data, status), on_executor_thread=False)
		for handle in self._on_ping:
			if handle(self, conn, addr, login_data, status):
				return False

		send_package(conn, 0x00, encode_json(status.to_json()))
		# recv ping packet
		pkt = recv_package(conn)
		if pkt.id == 0x01:
			d = pkt.read_long()
			send_package(conn, 0x01, encode_long(d))
		return False

	def handle_ping_1_6(self, conn: socket.socket, addr: tuple[str, int]):
		res = '\xa71\x00'
		res += str(0) + '\x00'
		res += 'Unsupported' + '\x00'
		res += self.modt + '\x00'
		res += '0' + '\x00' + '0'
		conn.sendall(b'\xff' + len(res).to_bytes(2, byteorder='big') + res.encode('utf-16-be'))

	def generate_secret(self) -> bytes:
		return os.urandom(16)

	def generate_verify_token(self) -> bytes:
		return os.urandom(4)

	def calc_server_hash(self, sid: str, secret: bytes) -> str:
		assert self._enabled_packet_proxy
		h = hashlib.sha1()
		h.update(sid.encode('utf8'))
		h.update(secret)
		h.update(self._private_key.publickey().export_key('DER'))
		d = int.from_bytes(h.digest(), signed=True)
		return f'{d:x}'

def proxy_conn_stream(c1, c2, addr: tuple[str, int], *, final=None, **kwargs):
	cond = threading.Condition(threading.Lock())
	finished = False
	def waiter():
		nonlocal finished
		with cond:
			if finished:
				return
			cond.wait()
	def final0():
		nonlocal finished
		with cond:
			if finished:
				return
			finished = True
			cond.notify_all()
		if final is not None:
			final()

	stream_forwarder(c1, c2, addr, final=final0, **kwargs)
	stream_forwarder(c2, c1, addr, final=final0, **kwargs)
	return waiter

@MCDR.new_thread('lp_stream_forwarder')
def stream_forwarder(src, dst, addr: tuple[str, int], *, chunk_size: int = 1024 * 128, final=None): # chunk_size = 128KB
	try:
		while True:
			buf = src.recv(chunk_size)
			if len(buf) == 0:
				break
			dst.sendall(buf)
	except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, OSError):
		pass
	except Exception as e:
		log_warn('Error when handle[{0[0]}:{0[1]}]: {1}'.format(addr, str(e)))
		traceback.print_exc()
	finally:
		src.close()
		dst.close()
		if final is not None:
			final()

def proxy_conn_packet(c: Conn, *, final=None, **kwargs):
	cond = threading.Condition(threading.Lock())
	finished = False
	def waiter():
		nonlocal finished
		with cond:
			if finished:
				return
			cond.wait()
	def final0():
		nonlocal finished
		with cond:
			if finished:
				return
			finished = True
			if c.isalive:
				c.disconnect()
			cond.notify_all()
		if final is not None:
			final()

	c.register_packet('login_encryption_response', _handle_login_encryption_response)
	c.register_packet('login_acknowledged', _handle_login_acknowledged, priority=-1000)
	c.register_packet('configuration_acknowledge_finish_configuration', _handle_configuration_acknowledge_finish_configuration, priority=-1000)
	c.register_packet('login_encryption_request', _handle_login_encryption_request)
	c.register_packet('login_success', _handle_login_success)
	c.register_packet('login_set_compression', _handle_login_set_compression)

	from .packet_patcher import patch_connection
	patch_connection(c)

	if c.server.online_mode:
		verify_token = c.server.generate_verify_token()
		c._custom_data['client_verify_token'] = verify_token
		encrypt_req = c.new_packet('login_encryption_request').\
			write_string('').\
			write_bytearray(c.server._private_key.public_key().export_key('DER')).\
			write_bytearray(verify_token)
		if c.protocol >= Protocol.V1_20_5:
			encrypt_req.write_bool(True)
		debug(f'sending encryption request')
		encrypt_req.send()

	packet_forwarder(c, True, c.addr, final=final0, **kwargs)
	packet_forwarder(c, False, c.addr, final=final0, **kwargs)
	return waiter

@MCDR.new_thread('lp_packet_forwarder')
def packet_forwarder(c: Conn, c2s: bool, addr: tuple[str, int], *, final=None):
	receiver, sender = (c.recv_client, c.send_server) if c2s else (c.recv_server, c.send_client)

	cached_packets: list[bytes] = []
	try:
		while True:
			reader = receiver()
			if reader is None:
				break
			if len(cached_packets) > 0 and c.client_status == c.server_status:
				for p in cached_packets:
					sender(p)
				cached_packets.clear()
			event = PacketEvent(c, reader, is_client=c2s)
			c.emit_packet(event)
			if not event.canceled:
				if c.client_status != c.server_status:
					cached_packets.append(reader.data)
					continue
				sender(reader.data)
	except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, OSError):
		pass
	except Exception as e:
		log_warn('Error when handle[{0[0]}:{0[1]}]: {1}'.format(addr, str(e)))
		traceback.print_exc()
	finally:
		if final is not None:
			final()

### C2S ###

def _handle_login_encryption_response(event: PacketEvent):	
	event.cancel()

	c = event.conn
	packet = event.reader
	encrypted_secret = packet.read_bytearray()
	encrypted_verify_token: bytes | None = None
	if Protocol.V1_19_3 > c.protocol and c.protocol >= Protocol.V1_19:
		has_verify_token = packet.read_bool()
		if has_verify_token:
			encrypted_verify_token = packet.read_bytearray()
		else:
			salt = packet.read_long()
			signature = packet.read_bytearray()
	else:
		encrypted_verify_token = packet.read_bytearray()
	secret = c.server._cipher.decrypt(encrypted_secret, None)
	assert secret is not None

	debug(f'Client connection encrypted')
	encryptor = Encryptor(secret)
	assert not isinstance(c._wrapped_conn_client, EncryptedConn)
	c._wrapped_conn_client = EncryptedConn(c._wrapped_conn_client, encryptor)

	if encrypted_verify_token is not None:
		# TODO: salt-signature verify version
		verify_token = c.server._cipher.decrypt(encrypted_verify_token, None)
		if verify_token != c._custom_data['client_verify_token']:
			c.kick('verify token incorrect')
			return

	if c.server.online_mode:
		client_hash_id = c.server.calc_server_hash('', secret)
		debug('requesting client has joined', c.name, client_hash_id)
		time.sleep(0.5)
		data = mojang.get_has_joined(c.name, client_hash_id)
		debug('requested client has joined', data)
		if data is None:
			c.kick('client did not send join request')
			return
		c._custom_data['uuid'] = uuid.UUID(data['id'])
		c._custom_data['name'] = data['name']
		if 'properties' in data:
			c._custom_data['properties'] = data['properties']

	buf = PacketBuffer()
	buf.write_varint(0x02)
	buf.write_uuid(c._custom_data['uuid'])
	buf.write_string(c._custom_data['name'])
	if c.protocol >= Protocol.V1_19:
		properties = c._custom_data['properties']
		buf.write_varint(len(properties))
		for prop in properties:
			buf.write_string(prop['name'])
			buf.write_string(prop['value'])
			has_sig = 'signature' in prop
			buf.write_bool(has_sig)
			if has_sig:
				buf.write_string(prop['signature'])
		if Protocol.V1_21_1 >= c.protocol and c.protocol >= Protocol.V1_20_5:
			buf.write_bool(True) # Strict Error Handling
	c.send_client(buf.data)

	if c.protocol < Protocol.V1_21:
		c._client_status = ConnStatus.PLAY
		if c.server_status != ConnStatus.LOGIN:
			c.server._mcdr_server.dispatch_event(ON_POST_LOGIN, (c, ), on_executor_thread=False)
			c.server._mcdr_server.dispatch_event(ON_PLAY, (c, ), on_executor_thread=False)

def _handle_login_acknowledged(event: PacketEvent):
	event.cancel()
	c = event.conn
	c._client_status = ConnStatus.CONFIGURATION
	c.send_server(event.reader.data)
	c._server_status = ConnStatus.CONFIGURATION
	c.server._mcdr_server.dispatch_event(ON_POST_LOGIN, (c, ), on_executor_thread=False)

def _handle_configuration_acknowledge_finish_configuration(event: PacketEvent):
	event.cancel()
	c = event.conn
	c._client_status = ConnStatus.PLAY
	c.send_server(event.reader.data)
	c._server_status = ConnStatus.PLAY
	c.server._mcdr_server.dispatch_event(ON_PLAY, (c, ), on_executor_thread=False)

### S2C ###

def _handle_login_encryption_request(event: PacketEvent):
	KICK_MESSAGE = 'minecraft server enabled authorization, please disable first'

	event.cancel()

	c = event.conn
	packet = event.reader
	server_id = packet.read_string()
	public_key = packet.read_bytearray()
	verify_token = packet.read_bytearray()
	if c.protocol < Protocol.V1_20_5:
		c.kick(KICK_MESSAGE)
		return
	should_auth = packet.read_bool()
	if should_auth:
		c.kick(KICK_MESSAGE)
		return

	secret = c.server.generate_secret()
	encrypted_secret = c.server._cipher.encrypt(secret)
	encrypted_verify_token = c.server._cipher.encrypt(verify_token)
	server_hash_id = c.server.calc_server_hash(server_id, secret)
	c._custom_data['server_hash_id'] = server_hash_id
	buf = PacketBuffer()
	buf.write_varint(0x01)
	buf.write_bytearray(encrypted_secret)
	if Protocol.V1_19_3 > c.protocol and c.protocol >= Protocol.V1_19:
		buf.write_bool(True)
	buf.write_bytearray(encrypted_verify_token)
	c.send_server(buf.data)

	debug(f'Server connection encrypted')
	encryptor = Encryptor(secret)
	assert not isinstance(c._wrapped_conn_server, EncryptedConn)
	c._wrapped_conn_server = EncryptedConn(c._wrapped_conn_server, encryptor)

def _handle_login_success(event: PacketEvent):
	event.cancel()

	c = event.conn
	c._custom_data['server_uuid'] = event.reader.read_uuid()
	debug('Serverside login success', c, 'with uuid', c._custom_data['server_uuid'])

	if c.protocol < Protocol.V1_21:
		c._server_status = ConnStatus.PLAY
	if 'client_verify_token' in c._custom_data:
		return
	if c.client_status != ConnStatus.LOGIN: # c.protocol < Protocol.V1_21:
		c.server._mcdr_server.dispatch_event(ON_POST_LOGIN, (c, ), on_executor_thread=False)
		c.server._mcdr_server.dispatch_event(ON_PLAY, (c, ), on_executor_thread=False)
		return
	if 'uuid' in c._custom_data:
		buf = PacketBuffer()
		buf.write_varint(0x02)
		buf.write_uuid(c._custom_data['uuid'])
		buf.write_string(c._custom_data['name'])
		if c.protocol >= Protocol.V1_19:
			properties = c._custom_data['properties']
			buf.write_varint(len(properties))
			for prop in properties:
				buf.write_string(prop['name'])
				buf.write_string(prop['value'])
				has_sig = 'signature' in prop
				buf.write_bool(has_sig)
				if has_sig:
					buf.write_string(prop['signature'])
			if Protocol.V1_21_1 >= c.protocol and c.protocol >= Protocol.V1_20_5:
				buf.write_bool(True)
		c.send_client(buf.data)
	else:
		c.send_client(event.reader.data)
	if c.protocol < Protocol.V1_21:
		c._client_status = ConnStatus.PLAY
		c.server._mcdr_server.dispatch_event(ON_POST_LOGIN, (c, ), on_executor_thread=False)
		c.server._mcdr_server.dispatch_event(ON_PLAY, (c, ), on_executor_thread=False)

def _handle_login_set_compression(event: PacketEvent):
	event.cancel()

	c = event.conn
	compress_threshold = event.reader.read_varint()
	c._server_compress_threshold = compress_threshold
	c.send_client(event.reader.data)
	c._client_compress_threshold = compress_threshold
