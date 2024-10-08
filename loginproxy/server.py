
import abc
import enum
import functools
import ipaddress
import os
import socket
import threading
import time
import traceback
import zlib
from abc import abstractmethod
from math import *
from typing import final, Any, Self, Callable

import mcdreforged.api.all as MCDR

from kpi.config import Properties
from .constants import *
from .configs import *
from .utils import *
from .encoder import *

__all__ = [
	# 'ServerStatus',
	'ConnStatus', 'Conn',
	'ProxyServer',
]

# class ServerStatus:
# 	def __init__(self, version: str, protocol: int,
# 		max_player: int, online_player: int, sample_players: list[dict],
# 		description: dict, favicon: str | None,
# 		enforcesSecureChat: bool):
# 		self.version = version
# 		self.protocol = protocol
# 		self.max_player = max_player
# 		self.online_player = online_player
# 		self.sample_players = sample_players
# 		self.description = description
# 		self.favicon = favicon
# 		self.enforcesSecureChat = False

# 	def to_json(self) -> dict:
# 		res: dict = {
# 			'version': {
# 				'name': self.version,
# 				'protocol': self.protocol,
# 			},
# 			'players': {
# 				'max': self.max_player,
# 				'online': self.online_player,
# 				'sample': self.sample_players,
# 			},
# 			'description': self.description,
# 		}
# 		if self.enforcesSecureChat:
# 			res['enforcesSecureChat'] = True
# 		return res

# 	@classmethod
# 	def from_json(cls, value: dict) -> Self:
# 		version = value['version']['name']
# 		protocol = value['version']['protocol']
# 		max_player = value['players']['max']
# 		online_player = value['players']['online']
# 		sample_players = value['players'].get('sample', [])
# 		description = value['description']
# 		favicon = value.get('favicon', None)
# 		enforcesSecureChat = value.get('enforcesSecureChat', False)
# 		return cls(version, protocol,
# 			max_player, online_player, sample_players,
# 			description, favicon,
# 			enforcesSecureChat)

class ConnStatus(int, enum.Enum):
	HANDSHAKING = 0
	STATUS      = 1
	LOGIN       = 2
	PLAY        = 3

class Conn:
	def __init__(self, name: str, addr: tuple[str, int], conn, server: 'ProxyServer', conn2, login_data: dict):
		self._name = name
		self._addr = addr
		self._conn = conn
		self._conn2 = conn2
		self._login_data = login_data
		self._protocol = login_data['protocol']
		self._status = ConnStatus.HANDSHAKING
		self._compressed = False
		self._compress_threshold = -1
		self._secrect = None
		self._server = server
		self._alive = True
		self._kicking = None

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
	def conn(self):
		return self._conn

	@property
	def conn2(self):
		return self._conn2

	@property
	def login_data(self) -> dict:
		return self._login_data

	@property
	def protocol(self) -> int:
		return self._protocol

	@property
	def status(self) -> ConnStatus:
		return self._status

	@status.setter
	def status(self, status: ConnStatus):
		self._status = status

	@property
	def compressed(self) -> bool:
		return self._compressed

	@property
	def compress_threshold(self) -> int:
		return self._compress_threshold

	@compress_threshold.setter
	def compress_threshold(self, compress_threshold: int):
		self._compressed = compress_threshold >= 0
		self._compress_threshold = compress_threshold

	def _recvpkt(self, conn) -> PacketReader:
		leng = recv_varint(conn)
		leng1 = leng
		data_leng = 0
		if self.compressed:
			data_leng, size = recv_varint2(conn)
			leng -= size
		debug(f'Recving a packet; leng={leng}; compressed={self.compressed}; data_leng={data_leng}')
		data = b''
		while len(data) < leng:
			data += conn.recv(leng - len(data))
		if data_leng > 0:
			try:
				data = zlib.decompress(data)
			except zlib.error as e:
				debug(f'Compressed data: {repr(data)}')
				raise
		return PacketReader(data)

	def recvpkt(self) -> PacketReader:
		"""
		Recv packet from the client
		"""
		return self._recvpkt(self.conn)

	def recvpkt2(self) -> PacketReader:
		"""
		Recv packet from the server
		"""
		return self._recvpkt(self.conn2)

	def _sendpkt(self, conn, data: bytes, pid: int | None):
		if pid is not None:
			data = encode_varint(pid) + data
		if self.compressed:
			data_leng = 0
			if len(data) > self.compress_threshold:
				data_leng = len(data)
				data = zlib.compress(data)
			data = encode_varint(data_leng) + data
		conn.sendall(encode_varint(len(data)))
		conn.sendall(data)

	def sendpkt(self, data: bytes, pid: int | None):
		"""
		Send packet to the client
		"""
		self._sendpkt(self.conn, data, pid)

	def sendpkt2(self, data: bytes, pid: int | None):
		"""
		Send packet to the server
		"""
		self._sendpkt(self.conn2, data, pid)

	@property
	def server(self) -> 'ProxyServer':
		return self._server

	@property
	def isalive(self) -> bool:
		return self._alive

	def _set_close(self):
		assert self._alive
		self._alive = False
		if self._kicking is not None:
			self._kicking.cancel()

	def kick(self, reason: str = 'You have been kicked', *,
		server: MCDR.ServerInterface | None = None):
		if not self.isalive:
			return False
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

	def disconnect(self):
		log_info('Forced disconnect player {0}[{1[0]}:{1[1]}]'.format(self.name, self.addr))
		self.conn.close()
		self.server._pop_uconn(self.conn)

class ProxyServer:
	def __init__(self, server: MCDR.ServerInterface, base: str, config, whlist):
		cls = self.__class__
		self.__mcdr_server = server
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

		self._on_login = [cls.default_onlogin]
		self._on_ping = [cls.default_onping]
		self._lock = threading.Condition(threading.Lock())
		self.__sockets: list[socket.socket] = []
		self.__status = 0
		self._conns: dict[str, Conn] = {}
		self._uconns: set[socket.socket] = set() # underlying connections

	@property
	def base(self):
		return self._base

	@property
	def config(self):
		return self.__config

	@property
	def whlist(self):
		return self.__whlist

	@property
	def properties(self) -> Properties:
		return self._properties

	@property
	def server_addr(self) -> tuple[str, int]:
		return self._server_addr

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

	def _add_uconn(self, conn):
		with self._lock:
			self._uconns.add(conn)

	def _pop_uconn(self, conn):
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
		if not self.__mcdr_server.is_server_startup():
			return False
		log_info('Player {0}[[{1[0]}]:{1[1]}] trying to join'.format(name, addr))
		sokt = self.new_connection(login_data)

		c = Conn(name, addr, conn, self, sokt, login_data)
		with self._lock:
			if name in self._conns:
				send_package(conn, 0x00, encode_json({
					'text': 'LoginProxy: Player {} is already exists'.format(name),
				}))
				conn.close()
				self._uconns.discard(conn)
				return True
			self._conns[name] = c
		def final():
			with self._lock:
				self._uconns.discard(conn)
				self._conns.pop(c.name, None)
				c._set_close()
			self.__mcdr_server.dispatch_event(ON_LOGOFF, (self, c), on_executor_thread=False)
		proxy_conn(conn, sokt, addr, final=final)
		return True

	@staticmethod
	def default_onping(self, conn, addr: tuple[str, int], login_data: dict, res: dict):
		if 'description' not in res:
			res['description'] = {
				'text': self.modt,
			}
		if get_server_instance().is_server_startup():
			debug('Creating connection for ping...')
			sokt = self.new_connection(login_data)
			debug('Forward ping connection')
			waiter = proxy_conn(conn, sokt, addr, final=lambda: self._pop_uconn(conn))
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
			def canceler():
				nonlocal canceled
				canceled = True
			debug('Client [[{0[0]}]:{0[1]}] connecting'.format(addr))
			get_server_instance().dispatch_event(ON_CONNECT,
				(self, conn, addr, canceler), on_executor_thread=False)
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
			self.__mcdr_server.get_permission_level(name) < self.config.whitelist_level:
			debug('Disconnected {1}[[{0[0]}]:{0[1]}] for name not in whilelist'.format(addr, name))
			send_package(conn, 0x00, encode_json({
				'text': self.config.messages['whitelist.name'],
			}))
			return False

		canceled: int = 0 # 0: not canceled; 1: handled; 2: disconnected
		def canceler(handled: bool = False):
			nonlocal canceled
			canceled = 1 if handled else 2
		self.__mcdr_server.dispatch_event(ON_LOGIN,
			(self, conn, addr, name, login_data, canceler), on_executor_thread=False)
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

	def handle_ping_1_7(self, conn, addr, protocol: int, login_data: dict):
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

		res = {
			'version': {
				'name': 'Idle',
				'protocol': 0
			},
			'players': {
				'max': 1,
				'online': 0,
			}
		}
		self.__mcdr_server.dispatch_event(ON_PING,
			(self, conn, addr, login_data, res), on_executor_thread=False)
		for handle in self._on_ping:
			if handle(self, conn, addr, login_data, res):
				return False

		send_package(conn, 0x00, encode_json(res))
		# recv ping packet
		pkt = recv_package(conn)
		if pkt.id == 0x01:
			d = pkt.read_long()
			send_package(conn, 0x01, encode_long(d))
		return False

	def handle_ping_1_6(self, conn, addr):
		res = '\xa71\x00'
		res += str(0) + '\x00'
		res += 'Unsupported' + '\x00'
		res += self.modt + '\x00'
		res += '0' + '\x00' + '0'
		conn.sendall(b'\xff' + len(res).to_bytes(2, byteorder='big') + res.encode('utf-16-be'))

def do_once_wrapper(callback):
	did = False
	@functools.wraps(callback)
	def w(*args, **kwargs):
		if did:
			return
		did = True
		return callback(*args, **kwargs)
	return w

@MCDR.new_thread('lp_forwarder')
def forwarder(src, dst, addr, *, chunk_size: int = 1024 * 128, final=None): # chunk_size = 128KB
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

def proxy_conn(c1, c2, addr, *, final=None, **kwargs):
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

	forwarder(c1, c2, addr, final=final0, **kwargs)
	forwarder(c2, c1, addr, final=final0, **kwargs)
	return waiter
