
import io
import os
import json
import uuid
import socket
import traceback
import functools
import threading
from math import *

import mcdreforged.api.all as MCDR

from kpi.config import Properties
from .globals import *
from .utils import *
from .decoder import *

__all__ = [
	'ProxyServer', 'Conn'
]

class ProxyServer: pass

class Conn:
	def __init__(self, name: str, addr: tuple[str, int], conn, server: ProxyServer):
		self._name = name
		self.__addr = addr
		self.__conn = conn
		self._server = server

	@property
	def name(self) -> str:
		return self._name

	@property
	def addr(self) -> tuple[str, int]:
		return self.__addr

	@property
	def ip(self) -> str:
		return self.__addr[0]

	@property
	def server(self) -> ProxyServer:
		return self._server

	def kick(self, reason: str = 'You have been kicked', *, server: MCDR.ServerInterface = None):
		if server is None:
			server = get_config().server
		if len(get_config().kick_cmd) > 0:
			server.execute(get_config().kick_cmd.format(name=self.name, reason=reason))
			return
		self.disconnect()

	def disconnect(self):
		log_info('Forced disconnect player {0}[{1[0]}:{1[1]}]'.format(self.name, self.addr))
		self.__conn.close()

class ProxyServer:
	def __init__(self, base: str):
		self._base = base
		self._properties = Properties(os.path.join(self._base, 'server.properties'))
		self._server_addr = (self._properties.get_str('server-ip', '127.0.0.1'), self._properties.get_int('server-port', 25565))
		self._modt = self._properties.get_str('motd', 'A Minecraft Server')
		self._max_players = self._properties.get_int('max-players', 20)

		self._on_login = ProxyServer.default_onlogin
		self._lock = threading.Condition(threading.Lock())
		self._socket = None
		self._status = 0
		self._conns = LockedData([])

	@property
	def base(self):
		return self._base

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
		return self._conns.copy()

	@property
	def on_login(self):
		return self._on_login

	@on_login.setter
	def on_login(self, callback):
		self._on_login = callback

	def add_login_handle(self, callback):
		handle = self._on_login
		@functools.wraps(callback)
		def wrapper():
			if callback():
				return True
			return None if handle is None else handle()
		self.on_login = wrapper
		return wrapper

	@staticmethod
	def default_onlogin(self, conn, addr: tuple[str, int], name: str, login_data: dict):
		if not MCDR.ServerInterface.get_instance().is_server_startup():
			return False
		log_info('Player {0}[[{1[0]}:{1[1]}]] trying to join'.format(name, addr))
		sokt = self.new_connect(login_data)

		c = Conn(name, addr, conn, self)
		def final():
			with self._conns:
				if c in self._conns.d:
					c._server = None
					self._conns.d.remove(c)
		forwarder(conn, sokt, addr, final=final)
		forwarder(sokt, conn, addr, final=final)
		with self._conns:
			self._conns.d.append(c)
		return True

	def new_connect(self, login_data: dict):
		sokt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sokt.connect(self.server_addr)
		debug('Connected to [{0[0]}:{0[1]}]'.format(self.server_addr))
		send_package(sokt, 0x00,
			encode_varint(login_data['protocol']) +
			encode_string(login_data['host']) +
			encode_short(login_data['port']) +
			encode_varint(login_data['state'])
		)
		if login_data['state'] == 1:
			send_package(sokt, 0x00, b'')
		elif login_data['state'] == 2:
			send_package(sokt, 0x00,
				encode_string(login_data['name']) +
				encode_bool(login_data['has_sig']) +
				((encode_long(login_data['timestamp']) +
					encode_varint(len(login_data['pubkey'])) +
					login_data['pubkey'] +
					encode_varint(len(login_data['sign'])) +
					login_data['sign']
				) if login_data['has_sig'] else b'') +
				encode_bool(login_data['has_uuid']) +
				(login_data['uuid'].bytes if login_data['has_uuid'] else b'')
			)

		return sokt

	@new_thread
	def __run(self):
		handle = MCDR.new_thread('lp_handler')(self.handle)
		try:
			while True:
				conn, addr = self._socket.accept()
				handle(conn, addr)
		except ConnectionAbortedError:
			pass
		except Exception as e:
			log_error('Error when listening:', str(e))
			traceback.print_exc()
		finally:
			self._socket.close()
			with self._lock:
				self._socket = None
				self._status = 0
				self._lock.notify_all()

	def start(self):
		with self._lock:
			if self._status != 0:
				log_warn('Proxy server running')
				return
			self._status = 1
		try:
			self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			ip, port = get_config().proxy_addr['ip'], get_config().proxy_addr['port']
			self._socket.bind((ip, port))
			self._socket.listen(ceil(self.max_players * 3 / 2))
			log_info('Proxy server listening at {0}:{1}'.format(ip, port))
			self.__run()
		except:
			with self._lock:
				self._status = 0
			raise

	def stop(self):
		with self._lock:
			if self._status != 1:
				return
			self._status = 2
			self._socket.close()
			self._lock.wait()
			assert self._status == 0

	def handle(self, conn, addr: tuple[str, int]) -> bool:
		try:
			pid, pkt = recv_package(conn)
			if pid == 0xfe:
				if conn.recv(2) == b'\x01\xfa':
					self.handle_ping_1_6(conn, addr)
			elif pid == 0x00:
				login_data = {}
				protocol = pkt.read_varint()
				login_data['protocol'] = protocol
				login_data['host'] = pkt.read_string()
				login_data['port'] = pkt.read_short()
				state = pkt.read_varint()
				login_data['state'] = state
				if state == 1:
					pid, _ = recv_package(conn)
					if pid == 0x00:
						self.handle_ping_1_7(conn, addr, protocol, login_data)
				elif state == 2:
					pid, pkt = recv_package(conn)
					if pid == 0x00:
						self.handle_login(conn, addr, login_data, pkt)
		except ConnectionAbortedError:
			pass
		except Exception as e:
			log_warn('Error when handle[{0[0]}:{0[1]}]: {1}'.format(addr, str(e)))
			traceback.print_exc()
			conn.close()
		except:
			conn.close()
			raise

	def handle_login(self, conn, addr: tuple[str, int], login_data: dict, pkt: Packet):
		protocol = login_data['protocol']
		name = pkt.read_string()
		login_data['name'] = name
		has_sig = pkt.read_bool()
		login_data['has_sig'] = has_sig
		if has_sig:
			login_data['timestamp'] = pkt.read_long()
			login_data['pubkey'] = pkt.read(pkt.read_varint())
			login_data['sign'] = pkt.read(pkt.read_varint())
		has_uuid = pkt.read_bool()
		login_data['has_uuid'] = has_uuid
		if has_uuid:
			uid = pkt.read_uuid()
			login_data['uuid'] = uid

		if addr[0] in ListConfig.instance().bannedip:
			send_package(conn, 0x00, encode_json({
				'text': get_config().messages['banned.ip'],
			}))
			return
		if name in ListConfig.instance().banned:
			send_package(conn, 0x00, encode_json({
				'text': get_config().messages['banned.name'],
			}))
			return
		if self.on_login is not None and self.on_login(self, conn, addr, name, login_data):
			return
		send_package(conn, 0x00, encode_json({
			'text': 'LoginProxy: No login handle found'
		}))
		conn.close()

	def handle_ping_1_7(self, conn, addr, protocol: int, login_data: dict):
		if MCDR.ServerInterface.get_instance().is_server_startup():
			sokt = self.new_connect(login_data)
			forwarder(conn, sokt, addr)
			forwarder(sokt, conn, addr)
			return
		res = {
			'version': {'name': 'Sleeping', 'protocol': 0},
			'players': {
				'max': 0,
				'online': 0,
				# 'sample': [
				# 	{
				# 		'name': 'Server stopped, please join the game to start the server',
				# 		'id': '00000000-0000-0000-0000-000000000000'
				# 	}
				# ]
			}
		}
		res['description'] = {
			'text': self.modt
		}
		try:
			send_package(conn, 0x00, encode_json(res))
			# recv ping packet
			pid, pkt = recv_package(conn)
			if pid == 0x01:
				d = pkt.read_long()
				send_package(conn, 0x01, encode_long(d))
		finally:
			conn.close()

	def handle_ping_1_6(self, conn, addr):
		res = '\xa71\x00'
		res += str(0) + '\x00'
		res += 'Sleeping' + '\x00'
		res += self.modt + '\x00'
		res += '0' + '\x00' + '0'
		conn.sendall(b'\xff' + len(res).to_bytes(2, byteorder='big') + res.encode('utf-16-be'))
		conn.close()

@MCDR.new_thread('lp_forwarder')
def forwarder(src, dst, addr, *, chunk_size: int = 1024 * 128, final=None): # chunk_size = 128KB
	try:
		while True:
			buf = src.recv(chunk_size)
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
